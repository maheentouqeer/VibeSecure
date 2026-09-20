"""Organization invite links."""
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import auth, db, invites, limits, main
from backend.db import Base, engine
from test_accounts import _add_sub, _as, _FakeJwks, _user_id


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in ("ENFORCE_PLAN_LIMITS", "FRONTEND_URL", "INVITE_TTL_DAYS", "INVITE_RATE_LIMIT_PER_HOUR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


@pytest.fixture()
def org(client):
    owner = _as("owner", "owner@x.test")
    admin = _as("admin", "admin@x.test")
    member = _as("member", "member@x.test")
    for h in (admin, member):
        client.get("/me", headers=h)
    org_id = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()["id"]
    client.post(f"/orgs/{org_id}/members", json={"email": "admin@x.test", "role": "admin"}, headers=owner)
    client.post(f"/orgs/{org_id}/members", json={"email": "member@x.test"}, headers=owner)
    return {"id": org_id, "owner": owner, "admin": admin, "member": member}


def _invite(client, org, who="owner", **body):
    return client.post(f"/orgs/{org['id']}/invites", json=body, headers=org[who])


def _roles(org_id):
    with db.SessionLocal() as s:
        return {m.user.clerk_user_id: m.role for m in s.query(db.Membership).filter_by(org_id=org_id)}


def _expire(invite_id):
    with db.SessionLocal() as s:
        s.get(db.OrgInvite, invite_id).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        s.commit()


# ================================= creating =================================


def test_owner_and_admin_can_create_member_invites(client, org):
    for who in ("owner", "admin"):
        resp = _invite(client, org, who)
        assert resp.status_code == 201 and resp.json()["role"] == "member"
        assert len(resp.json()["token"]) >= 40


def test_creating_invites_requires_membership_and_admin_rights(client, org):
    assert _invite(client, org, "member").status_code == 403
    assert client.post(f"/orgs/{org['id']}/invites", json={}, headers=_as("stranger")).status_code == 404
    assert client.post(f"/orgs/{org['id']}/invites", json={}).status_code == 401
    assert client.post("/orgs/nope/invites", json={}, headers=org["owner"]).status_code == 404


def test_only_the_owner_can_create_admin_invites(client, org):
    assert _invite(client, org, "admin", role="admin").status_code == 403
    assert _invite(client, org, "owner", role="admin").status_code == 201
    assert _invite(client, org, "owner", role="owner").status_code == 422  # ownership only moves via transfer


@pytest.mark.parametrize("bad", ["not-an-email", "a b@x.test", "@", "a@", "@x.test", "a@b", "a@@x.test"])
def test_email_must_look_like_an_email(client, org, bad):
    assert _invite(client, org, email=bad).status_code == 422
    with db.SessionLocal() as s:
        assert s.query(db.OrgInvite).count() == 0


def test_a_normal_address_is_accepted_and_normalized(client, org):
    assert _invite(client, org, email="  New.Person+tag@Example.Test ").json()["email"] == "new.person+tag@example.test"


def test_inviting_an_existing_member_is_refused(client, org):
    assert _invite(client, org, email="MEMBER@x.test").status_code == 409


def test_the_token_is_returned_once_and_only_its_hash_is_stored(client, org):
    created = _invite(client, org, email="new@x.test").json()
    token = created["token"]

    with db.SessionLocal() as s:
        row = s.query(db.OrgInvite).one()
        stored = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    assert token not in map(str, stored.values())
    assert stored["token_hash"] == invites._hash(token) and len(stored["token_hash"]) == 64

    listing = client.get(f"/orgs/{org['id']}/invites", headers=org["owner"])
    assert token not in listing.text and "token" not in listing.json()[0]


def test_the_link_uses_frontend_url_when_configured(client, org, monkeypatch):
    assert _invite(client, org).json()["url"] is None
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.test/")
    created = _invite(client, org).json()
    assert created["url"] == f"https://app.example.test?invite={created['token']}"
    monkeypatch.setenv("FRONTEND_URL", "javascript:alert(1)")
    assert _invite(client, org).json()["url"] is None


def test_invites_expire_after_the_configured_number_of_days(client, org, monkeypatch):
    def days_left():
        resp = _invite(client, org).json()
        end = datetime.fromisoformat(resp["expires_at"]).replace(tzinfo=timezone.utc)
        return (end - datetime.now(timezone.utc)).total_seconds() / 86400

    assert 6.9 < days_left() < 7.1
    monkeypatch.setenv("INVITE_TTL_DAYS", "2")
    assert 1.9 < days_left() < 2.1
    monkeypatch.setenv("INVITE_TTL_DAYS", "9999")
    assert days_left() < 60.1  # capped
    monkeypatch.setenv("INVITE_TTL_DAYS", "garbage")
    assert 6.9 < days_left() < 7.1


def test_reinviting_the_same_address_replaces_the_old_link(client, org):
    first = _invite(client, org, email="new@x.test").json()
    second = _invite(client, org, email="NEW@x.test").json()

    assert len(client.get(f"/orgs/{org['id']}/invites", headers=org["owner"]).json()) == 1
    newcomer = _as("newcomer", "new@x.test")
    assert client.post("/invites/accept", json={"token": first["token"]}, headers=newcomer).status_code == 404
    assert client.post("/invites/accept", json={"token": second["token"]}, headers=newcomer).status_code == 200


def test_pending_invites_per_org_are_capped(client, org, monkeypatch):
    monkeypatch.setattr(invites, "MAX_PENDING_PER_ORG", 3)
    assert [_invite(client, org).status_code for _ in range(4)] == [201, 201, 201, 429]


# =============================== seats and plans ============================


def test_pending_invites_hold_seats_when_plans_are_enforced(client, org, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    resp = _invite(client, org)  # a free org has 1 seat and already has 3 members
    assert resp.status_code == 402 and "seat" in resp.json()["detail"]

    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")  # 5 seats, 3 taken
    assert [_invite(client, org).status_code for _ in range(3)] == [201, 201, 402]  # 2 free seats


def test_a_pending_invite_blocks_a_direct_add_that_would_exceed_the_seats(client, org, monkeypatch):
    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    _invite(client, org)
    _invite(client, org)  # 3 members + 2 pending = 5 seats
    client.get("/me", headers=_as("extra", "extra@x.test"))
    resp = client.post(f"/orgs/{org['id']}/members", json={"email": "extra@x.test"}, headers=org["owner"])
    assert resp.status_code == 402


def test_revoking_or_accepting_frees_the_pending_seat_accounting(client, org, monkeypatch):
    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    a, b = _invite(client, org).json(), _invite(client, org).json()
    assert _invite(client, org).status_code == 402  # full

    client.delete(f"/orgs/{org['id']}/invites/{a['id']}", headers=org["owner"])
    assert _invite(client, org).status_code == 201  # the revoked seat is free again

    client.post("/invites/accept", json={"token": b["token"]}, headers=_as("joiner", "j@x.test"))
    assert _invite(client, org).status_code == 402  # accepted: now a member, still full


# ============================ listing and revoking ==========================


def test_listing_shows_only_pending_invites_to_admins(client, org):
    keep = _invite(client, org, email="keep@x.test").json()
    gone = _invite(client, org, email="gone@x.test").json()
    used = _invite(client, org).json()
    old = _invite(client, org).json()
    client.delete(f"/orgs/{org['id']}/invites/{gone['id']}", headers=org["owner"])
    client.post("/invites/accept", json={"token": used["token"]}, headers=_as("u", "u@x.test"))
    _expire(old["id"])

    listed = client.get(f"/orgs/{org['id']}/invites", headers=org["admin"]).json()
    assert [i["id"] for i in listed] == [keep["id"]]
    assert client.get(f"/orgs/{org['id']}/invites", headers=org["member"]).status_code == 403
    assert client.get(f"/orgs/{org['id']}/invites", headers=_as("stranger")).status_code == 404


def test_a_revoked_invite_can_no_longer_be_used(client, org):
    created = _invite(client, org).json()
    assert client.delete(f"/orgs/{org['id']}/invites/{created['id']}", headers=org["owner"]).status_code == 204
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("x", "x@x.test")).status_code == 404
    assert client.delete(f"/orgs/{org['id']}/invites/{created['id']}", headers=org["owner"]).status_code == 404  # already gone


def test_revoke_permissions_and_cross_org_safety(client, org):
    admin_invite = _invite(client, org, role="admin").json()
    member_invite = _invite(client, org).json()
    assert client.delete(f"/orgs/{org['id']}/invites/{admin_invite['id']}", headers=org["admin"]).status_code == 403
    assert client.delete(f"/orgs/{org['id']}/invites/{member_invite['id']}", headers=org["member"]).status_code == 403
    assert client.delete(f"/orgs/{org['id']}/invites/{member_invite['id']}", headers=org["admin"]).status_code == 204

    other = client.post("/orgs", json={"name": "Other"}, headers=_as("someone")).json()["id"]
    assert client.delete(f"/orgs/{other}/invites/{admin_invite['id']}", headers=_as("someone")).status_code == 404  # not their org's invite
    assert client.get(f"/orgs/{other}/invites", headers=_as("someone")).json() == []


# ================================== preview =================================


def test_preview_needs_no_sign_in_and_reveals_little(client, org):
    created = _invite(client, org, email="new@x.test", role="admin").json()
    resp = client.get("/invites/preview", params={"token": created["token"]})
    assert resp.status_code == 200
    assert resp.json()["organization"] == "Cohort" and resp.json()["role"] == "admin"
    assert resp.json()["restricted_to_email"] is True
    assert "new@x.test" not in resp.text and "owner@x.test" not in resp.text


def test_every_kind_of_bad_token_gets_the_same_answer(client, org):
    good = _invite(client, org).json()
    revoked = _invite(client, org).json()
    expired = _invite(client, org).json()
    used = _invite(client, org).json()
    client.delete(f"/orgs/{org['id']}/invites/{revoked['id']}", headers=org["owner"])
    _expire(expired["id"])
    client.post("/invites/accept", json={"token": used["token"]}, headers=_as("u", "u@x.test"))

    answers = {
        (r.status_code, r.json()["detail"])
        for r in (
            client.get("/invites/preview", params={"token": t})
            for t in (revoked["token"], expired["token"], used["token"], "x" * 43, "definitely-not-a-real-token")
        )
    }
    assert answers == {(404, "This invite is invalid or has expired.")}
    assert client.get("/invites/preview", params={"token": good["token"]}).status_code == 200


def test_preview_validates_its_input(client):
    assert client.get("/invites/preview").status_code == 422
    assert client.get("/invites/preview", params={"token": "short"}).status_code == 422


# ================================== accepting ===============================


def test_a_brand_new_user_can_sign_up_and_join(client, org):
    created = _invite(client, org, role="admin").json()
    newcomer = _as("brand_new", "new@x.test")  # never seen by the API before this request

    resp = client.post("/invites/accept", json={"token": created["token"]}, headers=newcomer)

    assert resp.status_code == 200 and resp.json()["organization"] == "Cohort" and resp.json()["role"] == "admin"
    assert _roles(org["id"])["brand_new"] == "admin"
    assert client.get("/me", headers=newcomer).json()["orgs"][0]["name"] == "Cohort"
    assert client.get(f"/orgs/{org['id']}/dashboard", headers=newcomer).status_code == 200  # admin invite: works


def test_accepting_requires_sign_in(client, org):
    created = _invite(client, org).json()
    assert client.post("/invites/accept", json={"token": created["token"]}).status_code == 401
    assert client.get("/invites/preview", params={"token": created["token"]}).status_code == 200  # still unused


def test_an_invite_works_exactly_once(client, org):
    created = _invite(client, org).json()
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("a", "a@x.test")).status_code == 200
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("b", "b@x.test")).status_code == 404
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("a", "a@x.test")).status_code == 404
    with db.SessionLocal() as s:
        row = s.query(db.OrgInvite).one()
        assert row.accepted_at is not None and row.accepted_by == _user_id(client, _as("a"))


def test_only_one_of_many_simultaneous_accepts_gets_in(client, org):
    created = _invite(client, org).json()
    users = [_as(f"racer{i}", f"r{i}@x.test") for i in range(6)]
    for h in users:
        client.get("/me", headers=h)
    codes, barrier = [], threading.Barrier(6)

    def go(h):
        barrier.wait()
        codes.append(client.post("/invites/accept", json={"token": created["token"]}, headers=h).status_code)

    threads = [threading.Thread(target=go, args=(h,)) for h in users]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sorted(codes) == [200] + [404] * 5
    assert sum(1 for name in _roles(org["id"]) if name.startswith("racer")) == 1


def test_expired_and_garbage_tokens_are_rejected(client, org):
    created = _invite(client, org).json()
    _expire(created["id"])
    newcomer = _as("n", "n@x.test")
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=newcomer).status_code == 404
    assert client.post("/invites/accept", json={"token": "x" * 43}, headers=newcomer).status_code == 404
    assert client.post("/invites/accept", json={"token": "short"}, headers=newcomer).status_code == 422
    assert "n" not in _roles(org["id"])


def test_email_restricted_invites_only_work_for_that_address(client, org):
    created = _invite(client, org, email="Right@X.test").json()
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("wrong", "wrong@x.test")).status_code == 403
    no_email = {"Authorization": _as("noemail")["Authorization"]}  # a token without an email claim
    denied = client.post("/invites/accept", json={"token": created["token"]}, headers=no_email)
    assert denied.status_code == 403 and "verify" in denied.json()["detail"]
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("right", "right@x.test")).status_code == 200
    assert _roles(org["id"]).get("right") == "member" and "wrong" not in _roles(org["id"])


def test_a_refused_attempt_does_not_use_up_the_invite(client, org):
    created = _invite(client, org, email="right@x.test").json()
    client.post("/invites/accept", json={"token": created["token"]}, headers=_as("wrong", "wrong@x.test"))
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("right", "right@x.test")).status_code == 200


def test_link_only_invites_work_for_anyone_including_users_without_an_email_claim(client, org):
    created = _invite(client, org).json()
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("anon_email")).status_code == 200


def test_an_existing_member_gets_a_409_and_the_invite_is_not_wasted(client, org):
    created = _invite(client, org).json()
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=org["member"]).status_code == 409
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("fresh", "f@x.test")).status_code == 200


def test_accepting_respects_the_seat_limit_without_consuming_the_invite(client, org, monkeypatch):
    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    a, b = _invite(client, org).json(), _invite(client, org).json()  # 3 members + 2 pending = full
    # a seat disappears out from under the invite (a member is added another way in the meantime)
    client.get("/me", headers=_as("sneak", "sneak@x.test"))
    with db.SessionLocal() as s:
        s.add(db.Membership(user_id=_user_id(client, _as("sneak")), org_id=org["id"], role="member"))
        s.commit()

    full = client.post("/invites/accept", json={"token": a["token"]}, headers=_as("j1", "j1@x.test"))
    assert full.status_code == 402
    with db.SessionLocal() as s:
        assert s.query(db.OrgInvite).filter(db.OrgInvite.accepted_at.isnot(None)).count() == 0  # not consumed


def test_accept_and_preview_are_rate_limited_per_ip(client, org, monkeypatch):
    monkeypatch.setenv("INVITE_RATE_LIMIT_PER_HOUR", "3")
    codes = [client.get("/invites/preview", params={"token": "x" * 43}).status_code for _ in range(4)]
    assert codes == [404, 404, 404, 429]
    assert client.post("/invites/accept", json={"token": "x" * 43}, headers=_as("a")).status_code == 429  # shared bucket


# ================================== cleanup =================================


def test_deleting_an_org_deletes_its_invites(client, org):
    _invite(client, org)
    _invite(client, org)
    with db.SessionLocal() as s:
        s.query(db.Membership).filter(db.Membership.role != "owner").delete()
        s.commit()
    assert client.delete(f"/orgs/{org['id']}", headers=org["owner"]).status_code == 204
    with db.SessionLocal() as s:
        assert s.query(db.OrgInvite).count() == 0


def test_deleting_an_account_removes_invites_it_sent_and_anonymizes_ones_it_accepted(client, org):
    from_admin = _invite(client, org, "admin").json()  # sent by the admin
    accepted = _invite(client, org, "owner").json()
    joiner = _as("joiner", "j@x.test")
    client.post("/invites/accept", json={"token": accepted["token"]}, headers=joiner)

    assert client.delete("/me", headers=org["admin"]).status_code == 204  # the admin leaves
    assert client.delete("/me", headers=joiner).status_code == 204  # the joiner leaves

    with db.SessionLocal() as s:
        remaining = s.query(db.OrgInvite).all()
        assert [i.id for i in remaining] == [accepted["id"]]  # the admin's pending invite is gone
        assert remaining[0].accepted_by is None
    assert client.post("/invites/accept", json={"token": from_admin["token"]}, headers=_as("z")).status_code == 404


def test_ownership_transfer_leaves_pending_invites_valid(client, org):
    created = _invite(client, org).json()
    client.post(f"/orgs/{org['id']}/transfer", json={"user_id": _user_id(client, org["admin"])}, headers=org["owner"])
    assert client.post("/invites/accept", json={"token": created["token"]}, headers=_as("n", "n@x.test")).status_code == 200


def test_the_claim_itself_is_atomic_when_two_accepts_truly_overlap(client, org, monkeypatch):
    """Forces the dangerous interleaving: both requests read the invite as still
    pending BEFORE either one claims it. Only the conditional UPDATE can keep
    them from both getting in (the plain race test above often never overlaps)."""
    created = _invite(client, org).json()
    users = [_as("first", "first@x.test"), _as("second", "second@x.test")]
    for h in users:
        client.get("/me", headers=h)

    barrier = threading.Barrier(2)
    real = invites._find_pending

    def find_then_wait(session, token):
        invite = real(session, token)
        barrier.wait(timeout=10)  # neither request may continue until BOTH have seen "pending"
        return invite

    monkeypatch.setattr(invites, "_find_pending", find_then_wait)
    codes = []

    def go(h):
        codes.append(client.post("/invites/accept", json={"token": created["token"]}, headers=h).status_code)

    threads = [threading.Thread(target=go, args=(h,)) for h in users]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sorted(codes) == [200, 404]
    joined = [name for name in _roles(org["id"]) if name in ("first", "second")]
    assert len(joined) == 1
    with db.SessionLocal() as s:
        assert s.query(db.OrgInvite).one().accepted_by is not None
