# Supabase Row Level Security (RLS) Security Reference Guide

## Vulnerability Overview: Missing Row Level Security
In Supabase and PostgreSQL applications, Row Level Security (RLS) is an access control mechanism that restricts which rows in a table can be selected, inserted, updated, or deleted by different database roles and users.

By default, when a table is created in PostgreSQL or Supabase (`CREATE TABLE ...`), RLS is **disabled** unless explicitly enabled.

## The Architecture & Threat Model in Vibe-Coded Apps
1. **Public Anon Key Exposure**: Lovable, FlutterFlow, and standard Supabase web applications bundle the `anon` public API key directly into the client-side JavaScript / TypeScript code (`createClient(SUPABASE_URL, SUPABASE_ANON_KEY)`).
2. **Direct PostgREST API Access**: Supabase automatically exposes all public tables over PostgREST REST and GraphQL APIs (`https://<project-ref>.supabase.co/rest/v1/<table>`).
3. **Exploit Consequence**: If RLS is disabled, anyone possessing the public `anon` key (trivially extracted from browser DevTools, network traffic, or public Git repositories) has full read and write access to the table. An attacker can execute `GET /rest/v1/users` or `DELETE /rest/v1/orders` without authentication, bypassing all frontend UI checks.

## Official Remediation (Vetted SQL Standards)

### Step 1: Enable RLS on the Table
```sql
ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;
```
Enabling RLS immediately blocks all public operations by default until an explicit policy is defined.

### Step 2: Define Granular Security Policies
Policies should enforce user isolation using Supabase authentication context (`auth.uid()`):

```sql
-- Allow users to read only their own rows
CREATE POLICY "Users can view own data"
ON <table_name>
FOR SELECT
USING (auth.uid() = user_id);

-- Allow authenticated users to insert rows for themselves
CREATE POLICY "Users can insert own data"
ON <table_name>
FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Allow users to update only their own rows
CREATE POLICY "Users can update own data"
ON <table_name>
FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- Allow users to delete only their own rows
CREATE POLICY "Users can delete own data"
ON <table_name>
FOR DELETE
USING (auth.uid() = user_id);
```

### Public / Read-Only Tables (e.g. Products, Catalogs)
If a table is intended to be publicly readable by unauthenticated visitors:
```sql
ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public read-only access"
ON <table_name>
FOR SELECT
TO anon, authenticated
USING (true);
```
Never allow unrestricted `INSERT`, `UPDATE`, or `DELETE` with `USING (true)` or `WITH CHECK (true)` on tables storing private or sensitive state.
