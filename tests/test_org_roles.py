"""Organization roles, ownership transfer, and the one-owner invariant."""
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from backend import auth, db, limits, main
from backend.db import Base, engine
from test_accounts import _as, _FakeJwks, _make_scan, _scan_for, _user_id


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.delenv("ENFORCE_PLAN_LIMITS", raising=False)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


@pytest.fixture()
def team(client):
    """owner + admin + two plain members, all in one organization."""
    users = {n: _as(n, f"{n}@x.test") for n in ("owner", "admin", "m1", "m2")}
    for h in users.values():
        client.get("/me", headers=h)
    org = client.post("/orgs", json={"name": "Cohort"}, headers=users["owner"]).json()
    for name, role in (("admin", "admin"), ("m1", "member"), ("m2", "member")):
        resp = client.post(f"/orgs/{org['id']}/members", json={"email": f"{name}@x.test", "role": role}, headers=users["owner"])
        assert resp.status_code == 201
    ids = {n: _user_id(client, h) for n, h in users.items()}
    return users, ids, org["id"]


def _roles(org_id):
    with db.SessionLocal() as s:
        return {m.user.clerk_user_id: m.role for m in s.query(db.Membership).filter_by(org_id=org_id)}


# ================================ role changes ==============================


def test_owner_can_promote_and_demote(client, team):
    users, ids, org = team
    url = f"/orgs/{org}/members/{ids['m1']}"

    assert client.patch(url, json={"role": "admin"}, headers=users["owner"]).json() == {"user_id": ids["m1"], "role": "admin"}
    assert _roles(org)["m1"] == "admin"
    assert client.patch(url, json={"role": "member"}, headers=users["owner"]).status_code == 200
    assert _roles(org)["m1"] == "member"


def test_only_the_owner_can_change_roles(client, team):
    users, ids, org = team
    url = f"/orgs/{org}/members/{ids['m1']}"
    assert client.patch(url, json={"role": "admin"}, headers=users["admin"]).status_code == 403
    assert client.patch(url, json={"role": "admin"}, headers=users["m2"]).status_code == 403
    assert client.patch(url, json={"role": "admin"}, headers=_as("stranger")).status_code == 404
    assert client.patch(url, json={"role": "admin"}).status_code == 401
    assert _roles(org)["m1"] == "member"


def test_role_change_input_is_validated(client, team):
    users, ids, org = team
    assert client.patch(f"/orgs/{org}/members/{ids['m1']}", json={"role": "owner"}, headers=users["owner"]).status_code == 422
    assert client.patch(f"/orgs/{org}/members/{ids['m1']}", json={"role": "root"}, headers=users["owner"]).status_code == 422
    assert client.patch(f"/orgs/{org}/members/nobody", json={"role": "admin"}, headers=users["owner"]).status_code == 404


def test_the_owners_own_role_cannot_be_patched(client, team):
    users, ids, org = team
    resp = client.patch(f"/orgs/{org}/members/{ids['owner']}", json={"role": "member"}, headers=users["owner"])
    assert resp.status_code == 400 and "transferring ownership" in resp.json()["detail"]
    assert _roles(org)["owner"] == "owner"


def test_a_promoted_admin_gains_dashboard_access_and_a_demoted_one_loses_it(client, team):
    users, ids, org = team
    dash = f"/orgs/{org}/dashboard"
    assert client.get(dash, headers=users["m1"]).status_code == 403
    client.patch(f"/orgs/{org}/members/{ids['m1']}", json={"role": "admin"}, headers=users["owner"])
    assert client.get(dash, headers=users["m1"]).status_code == 200
    client.patch(f"/orgs/{org}/members/{ids['m1']}", json={"role": "member"}, headers=users["owner"])
    assert client.get(dash, headers=users["m1"]).status_code == 403


# ============================ tightened permissions =========================


def test_admins_cannot_add_other_admins_but_can_add_members(client, team):
    users, ids, org = team
    client.get("/me", headers=_as("newbie", "newbie@x.test"))
    client.get("/me", headers=_as("newbie2", "newbie2@x.test"))
    url = f"/orgs/{org}/members"

    assert client.post(url, json={"email": "newbie@x.test", "role": "admin"}, headers=users["admin"]).status_code == 403
    assert client.post(url, json={"email": "newbie@x.test", "role": "member"}, headers=users["admin"]).status_code == 201
    assert client.post(url, json={"email": "newbie2@x.test", "role": "admin"}, headers=users["owner"]).status_code == 201


def test_admins_cannot_remove_other_admins_but_owner_can(client, team):
    users, ids, org = team
    client.post(f"/orgs/{org}/members", json={"email": "m1@x.test"}, headers=users["owner"])  # already a member: 409, harmless
    client.patch(f"/orgs/{org}/members/{ids['m1']}", json={"role": "admin"}, headers=users["owner"])

    assert client.delete(f"/orgs/{org}/members/{ids['m1']}", headers=users["admin"]).status_code == 403
    assert client.delete(f"/orgs/{org}/members/{ids['m2']}", headers=users["admin"]).status_code == 204  # plain member: fine
    assert client.delete(f"/orgs/{org}/members/{ids['m1']}", headers=users["owner"]).status_code == 204


def test_an_admin_can_still_leave_on_their_own(client, team):
    users, ids, org = team
    assert client.delete(f"/orgs/{org}/members/{ids['admin']}", headers=users["admin"]).status_code == 204


# ================================== transfer ================================


def test_transfer_swaps_owner_and_admin_and_updates_the_organization(client, team):
    users, ids, org = team
    resp = client.post(f"/orgs/{org}/transfer", json={"user_id": ids["m1"]}, headers=users["owner"])

    assert resp.status_code == 200
    assert resp.json() == {"org_id": org, "owner_user_id": ids["m1"], "previous_owner_role": "admin"}
    assert _roles(org) == {"owner": "admin", "admin": "admin", "m1": "owner", "m2": "member"}
    with db.SessionLocal() as s:
        assert s.get(db.Organization, org).owner_user_id == ids["m1"]


def test_after_transfer_the_new_owner_has_owner_powers_and_the_old_one_does_not(client, team):
    users, ids, org = team
    client.post(f"/orgs/{org}/transfer", json={"user_id": ids["m1"]}, headers=users["owner"])

    assert client.patch(f"/orgs/{org}/members/{ids['m2']}", json={"role": "admin"}, headers=users["m1"]).status_code == 200
    assert client.patch(f"/orgs/{org}/members/{ids['m2']}", json={"role": "member"}, headers=users["owner"]).status_code == 403
    assert client.post(f"/orgs/{org}/transfer", json={"user_id": ids["owner"]}, headers=users["owner"]).status_code == 403
    assert client.delete(f"/orgs/{org}", headers=users["owner"]).status_code == 403
    assert client.delete(f"/orgs/{org}", headers=users["m1"]).status_code == 204


def test_transfer_rules(client, team):
    users, ids, org = team
    url = f"/orgs/{org}/transfer"
    assert client.post(url, json={"user_id": ids["m1"]}, headers=users["admin"]).status_code == 403
    assert client.post(url, json={"user_id": ids["m1"]}, headers=users["m2"]).status_code == 403
    assert client.post(url, json={"user_id": ids["m1"]}, headers=_as("stranger")).status_code == 404
    assert client.post(url, json={"user_id": ids["m1"]}).status_code == 401
    assert client.post(url, json={"user_id": ids["owner"]}, headers=users["owner"]).status_code == 400  # to self
    assert client.post(url, json={"user_id": "nobody"}, headers=users["owner"]).status_code == 404
    outsider = _user_id(client, _as("outsider"))
    assert client.post(url, json={"user_id": outsider}, headers=users["owner"]).status_code == 404  # not a member
    assert client.post(url, json={}, headers=users["owner"]).status_code == 422
    assert _roles(org)["owner"] == "owner"  # every failed attempt left ownership untouched


def test_a_failed_transfer_does_not_leave_the_owner_demoted(client, team):
    users, ids, org = team
    client.post(f"/orgs/{org}/transfer", json={"user_id": "nobody"}, headers=users["owner"])
    assert _roles(org)["owner"] == "owner"
    with db.SessionLocal() as s:
        assert s.get(db.Organization, org).owner_user_id == ids["owner"]


def test_only_one_of_many_simultaneous_transfers_succeeds(client, team):
    users, ids, org = team
    codes, barrier = [], threading.Barrier(6)
    targets = [ids["m1"], ids["m2"], ids["admin"]] * 2

    def go(target):
        barrier.wait()
        codes.append(client.post(f"/orgs/{org}/transfer", json={"user_id": target}, headers=users["owner"]).status_code)

    threads = [threading.Thread(target=go, args=(t,)) for t in targets]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sorted(codes) == [200, 403, 403, 403, 403, 403]
    owners = [name for name, role in _roles(org).items() if role == "owner"]
    assert len(owners) == 1 and owners != ["owner"]


def test_account_deletion_rules_follow_the_transfer(client, team):
    users, ids, org = team
    assert client.delete("/me", headers=users["owner"]).status_code == 409  # owns an org with members
    client.post(f"/orgs/{org}/transfer", json={"user_id": ids["m1"]}, headers=users["owner"])

    assert client.delete("/me", headers=users["owner"]).status_code == 204  # now just an admin
    assert client.delete("/me", headers=users["m1"]).status_code == 409  # the new owner is blocked instead
    assert _roles(org)["m1"] == "owner"


def test_transferred_org_keeps_its_scans_and_dashboard(client, team):
    users, ids, org = team
    _make_scan(client, users["m1"], org_id=org)
    client.post(f"/orgs/{org}/transfer", json={"user_id": ids["m2"]}, headers=users["owner"])
    dash = client.get(f"/orgs/{org}/dashboard", headers=users["m2"]).json()
    assert dash["summary"]["projects"] == 1


# ============================ database invariant ============================


def test_the_database_itself_refuses_a_second_owner(client, team):
    users, ids, org = team
    with db.SessionLocal() as s:
        m1 = s.query(db.Membership).filter_by(org_id=org, user_id=ids["m1"]).one()
        m1.role = "owner"
        with pytest.raises(IntegrityError):
            s.commit()


def test_owners_of_different_orgs_do_not_conflict(client, team):
    users, ids, org = team
    other = client.post("/orgs", json={"name": "Second"}, headers=users["m1"])
    assert other.status_code == 201
    assert _roles(other.json()["id"])["m1"] == "owner"
