# auth-mcp

The example admin MCP server. It lets a person work with sites, routes, organisations, groups,
roles, people and the audit trail from an AI client, **as themselves**: with a Hydra token whose
scopes are their own permissions (or a subset they chose), re-checked on every call. Tokens are not
bound to an organisation: an org tool takes an explicit `org`, and jinbe decides. The server
has no credentials of its own. jinbe and OPA decide every call.

Status: **read wave (W3) + write wave**. Write tools are wired and direct (a key does what its holder
can do), decided by jinbe's delegation gate; `resend_verification_email`, `change_user_email` and the
bulk tools require jinbe ≥ wave17/mcp-endpoints. jinbe
serves the delegated identity path (`/api/mcp/token-info`, `/api/mcp/personal-keys/exchange`, the
MCP-audience token beside `X-Actor-Token`), behind the administrator's switch (Settings → AI
assistants), which is off until someone turns it on.

## Connect a client

The server URL is `MCP_RESOURCE`: in the sandbox, `https://mcp.authdev.dev.example.com/mcp`
(discovery: `/.well-known/oauth-protected-resource`). The snippets below use it. In the console,
Connections & keys shows the URL for your platform (what an administrator set in Settings → AI
assistants) and fills a newly created key into every snippet. The same guide is served over MCP as
the resource `docs://getting-started` and the prompt `getting-started` (`src/mcp/guide.ts`).

### Before you start

1. **An administrator must turn AI assistants on**: Settings → AI assistants. If they limited it to
   some groups, you must be in one of them.
2. **Create a key**: Connections & keys → Create key. Pick:
   - **All my permissions**: the key can do whatever you can, now and as your access changes.
   - **Choose permissions**: only the ones you tick, among those you hold.
   - **Expiry**: 1, 7 or 30 days. Keys always expire (30 days at most by default; an administrator
     can set a shorter maximum).
3. **Copy the key when it is shown**. It is displayed once and cannot be read back. Create one key
   per client, so each can be revoked on its own.

### Keep the key out of files

Put the key in an environment variable (from your shell profile or a secret manager). Never commit it
or paste it in a ticket or chat.

```sh
export example_MCP_KEY='stk_mcp_<your key>'
```

Every snippet below reads `example_MCP_KEY` (or the client's own secret storage) instead of
containing the key. The only exception is Claude Desktop, whose config file holds it.

### Claude Code

Just for you, in every project (saved in `~/.claude.json`; the shell expands the variable now):

```sh
claude mcp add --transport http --scope user example https://mcp.authdev.dev.example.com/mcp \
  --header "Authorization: Bearer $example_MCP_KEY"
```

For the whole team, in the project's `.mcp.json`. Single quotes keep `${example_MCP_KEY}` literal:
Claude Code expands it when it starts, so the file can be committed and each developer sets their
own key.

```sh
claude mcp add --transport http --scope project example https://mcp.authdev.dev.example.com/mcp \
  --header 'Authorization: Bearer ${example_MCP_KEY}'
```

Scopes: `--scope local` (default: you, this project only), `--scope project` (`.mcp.json`, shared),
`--scope user` (you, all projects). `-s` is the short form.

Check it:

```sh
claude mcp get example
# then, inside a Claude Code session:
/mcp
```

`example` should read *connected*, with its tools listed. To remove it:
`claude mcp remove example --scope user`.

### Claude Desktop

Claude Desktop starts only local (stdio) servers from its config file, so the
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridge (needs Node.js 18 or later) connects
it to this remote server. Custom connectors (Settings → Connectors → Add custom connector) take only a
URL and sign in with OAuth, so they cannot send a personal key.

Open Settings → Developer → Edit Config, which is:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "example": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp.authdev.dev.example.com/mcp",
        "--header",
        "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer stk_mcp_<your key>"
      }
    }
  }
}
```

There is deliberately no space after `Authorization:`, because some platforms split arguments on
spaces. `mcp-remote` substitutes `${AUTH_HEADER}` from `env`. This file holds the key, so keep it out
of backups and dotfile repos you share. Quit Claude Desktop completely and start it again. The tools
appear under the tools button in a new chat.

### Cursor

Add the server to `~/.cursor/mcp.json` (yours, for every project). Don't put it in a project's
`.cursor/mcp.json` if that file holds a key.

```json
{
  "mcpServers": {
    "example": {
      "url": "https://mcp.authdev.dev.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${env:example_MCP_KEY}"
      }
    }
  }
}
```

Cursor resolves `${env:…}` from the environment it was started in. Start it from a terminal where
the variable is set (`cursor .`), because an app opened from the Dock or Start menu does not see
your shell's variables. Check it in Cursor Settings → MCP: `example` should show a green dot and
its tools.

### VS Code (GitHub Copilot)

Run **MCP: Open User Configuration** from the Command Palette (or create `.vscode/mcp.json` in a
project):

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "example-mcp-key",
      "description": "example MCP key (stk_mcp_…)",
      "password": true
    }
  ],
  "servers": {
    "example": {
      "type": "http",
      "url": "https://mcp.authdev.dev.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${input:example-mcp-key}"
      }
    }
  }
}
```

VS Code asks for the key the first time the server starts and keeps it in its secret storage. The
file holds no key and can be committed. Start the server from the lens above its entry, then use it
from Copilot Chat in agent mode.

### curl smoke test

Each request stands alone: the server is stateless, so there is no session id to carry.

```sh
MCP_URL=https://mcp.authdev.dev.example.com/mcp

# 1. initialize: the server's name, capabilities and instructions
curl -s $MCP_URL \
  -H "Authorization: Bearer $example_MCP_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

# 2. tools/list: only the tools your key's permissions cover
curl -s $MCP_URL \
  -H "Authorization: Bearer $example_MCP_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# 3. who the key acts as
curl -s $MCP_URL \
  -H "Authorization: Bearer $example_MCP_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_my_identity","arguments":{}}}'
```

Without a key you get `401` with
`WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`, which
confirms the server is reachable.

### What a key can do

- **It acts as you.** The platform checks your permissions again on every call. If you lose a
  permission or a group, the key loses it at once. A key with chosen permissions is further limited
  to those.
- **The assistant sees only the tools your permissions cover.** `tools/list` differs from person to
  person.
- **Everything is recorded.** Calls appear in the audit trail under your name, together with the key
  they came through.

**Protected writes** (publish, pause, resume and roll back a site; change a user's email; add people
to groups; create or edit groups and service roles) work only with a key created with *protected actions* allowed: the second factor proven
when the key was created stands in, for 30 days at most. In production a key does not publish: it
asks with `request_site_apply`, and a person approves in the console.

**Never through a key**, whatever permissions it carries:

- deleting anything (sites, drafts, users, groups, memberships); revoking one of your own keys is the
  one exception (`revoke_my_key`);
- zones, the gateway configuration, sign-in settings or the AI assistant settings;
- resetting a second factor, creating a key, approving or rejecting a request;
- deleting a group or a role, exporting the policy bundle or the audit trail;
- changing your own account or groups.

### Tools

The server also serves this list itself. Read the resource `docs://getting-started` or use the
prompt `getting-started`: each tool is marked as available or not for *your* key.

| Tool | What it does | Needs |
|---|---|---|
| `get_my_identity` | Who this connection acts as, its effective scopes, read-only state, whether it may do protected actions (and until when), key, token expiry | any connection |
| `can_i` | Would this connection be allowed to run a tool (with these arguments), and the refusal it would get; no side effect | any connection |
| `get_my_permissions` | Your groups, roles and permissions as the policy engine resolves them | any connection |
| `list_orgs` | The organisations you administer (ids for the org tools) | any connection |
| `list_sites` | Sites with status (draft, live, attention, paused), host, versions | `sites:read` |
| `get_site` | One site's saved intent, version, etag and applied state | `sites:read` |
| `site_versions` | A site's version history | `sites:read` |
| `blast_radius` | What deleting or breaking a site would take with it | `sites:read` |
| `get_platform` | Environment, four-eyes mode, zones, reserved hosts | `sites:read` |
| `check_site_draft` | Lint a site draft | `sites:read` (preview with `sites:write`) |
| `match_request` | Which gateway rule and site route a request hits | `sites:read` |
| `render_template` | Render a header, cookie, payload or claims template as the gateway would | `sites:read` |
| `list_groups` | Groups and the roles they give per service | `groups:read` |
| `list_services` | Services known to the access model | `sites:read` |
| `list_roles` | A service's roles and their permissions | `sites:read` |
| `get_permission_catalog` | Every permission a service defines | `sites:read` |
| `explain_access` | Can this person call METHOD PATH, and why | `access:check` |
| `get_user_access` | One person's access: groups, roles, org grants | `access:read` |
| `find_users` | Find people by id, email, or part of an email or name | `users:read` |
| `search_audit` | Audit events you may read, filtered, newest first | `audit:read` |
| `get_audit_event` | One audit event by id | `audit:read` |
| `get_org` | One organisation and the groups you may grant in it | `org.members:read` |
| `list_org_users` | Members of one organisation | `org.members:read` |
| `list_org_grants` | Groups handed out in one organisation, per member | `org.members:read` |
| `create_site` | Start a new site as a draft from a template | `sites:write` |
| `save_site_draft` | Save a site's draft, with a security lint | `sites:write` |
| `update_site_routes` | Add, change or remove routes in the draft, up to 500 per call | `sites:write` |
| `import_openapi` | Preview, then commit, OpenAPI routes into the draft | `sites:write` |
| `diff_site` | What the draft or saved version changes against what is live | `sites:write` |
| `save_site_version` | Save the draft as a new version (etag-checked) | `sites:write` |
| `publish_site` | Apply a saved version (protected; production: request instead) | `sites:apply` |
| `request_site_apply` | Ask for a saved version to be applied; a person approves | `sites:write` |
| `pause_site` / `resume_site` | Stop or resume serving a site (protected) | `sites:apply` |
| `rollback_site` | Save an older version as new and apply it (protected) | `sites:apply` |
| `invite_user` | Create a user and mail an invitation; optional groups | `users:create` |
| `send_recovery_email` | Mail a user a recovery message | `users:recovery` |
| `send_login_link` | Mail a user a one-click sign-in link | `users:send_login_link` |
| `resend_verification_email` | Mail a verification link to an unverified address | `users:verify` |
| `change_user_email` | Change another user's sign-in address (protected) | `users:update_email` |
| `add_user_to_groups` | Add a user to groups, keeping the others (protected) | `groups.members:write` |
| `create_group` / `update_group` | Create a group, or change the roles it gives per service (protected) | `groups:write` |
| `set_site_roles` | Replace a service's roles and their permissions (protected) | `groups:write` |
| `plan_bulk` / `execute_bulk` / `get_bulk_job` | Dry-run, run and follow up to 200 items of one op: `sites.routes.upsert`, `users.invite`, `users.verification`, `groups.members.add` | the op's permission |
| `revoke_my_key` | Revoke one of your own keys (default: this one) | any connection |

Resources: `docs://getting-started`, `catalog://permissions`, `platform://`, `site://{name}`,
`org://{id}` (each listed when its tool is available).

#### Try asking

- "Who am I connected as, and what can this key do?"
- "List the sites and tell me which ones need attention."
- "Show the site `billing` and its version history."
- "What would break if the site `shop` went down?"
- "Explain access for alice@example.com to GET /api/billing/invoices."
- "Find the people whose email starts with bob@ and show their access."
- "Show the last 20 audit events."
- "Which requests were denied in the last hour?"
- "Who are the members of my organisation, and which groups do they hold?"

### Expiry and revocation

- Every key expires: 1, 7 or 30 days (30 at most by default, or less if an administrator set a
  shorter maximum). The key list shows when each one expires.
- **Revoke** on Connections & keys stops a key immediately. Clients using it are refused from their
  next call. Revoking cannot be undone, so create a new key to connect again.
- If a key leaks, revoke it and create another.

### Troubleshooting

| What you see | Meaning | What to do |
|---|---|---|
| `401 invalid_key` / `invalid_token` | The key expired, was revoked, or is incomplete. The whole value is `stk_mcp_<id>.<secret>`, after `Bearer `. | Check that the variable is set in the shell or app that starts the client. Otherwise create a new key. A client that suddenly opens a browser to "sign in" also got a 401. |
| `403 mcp_disabled`: "turned off by an administrator" | Settings → AI assistants is off. | Nothing to fix on your side. Keys are kept and work again when it is switched back on. |
| `403 mcp_disabled`: "not enabled for your groups" | AI assistants are limited to groups you are not in. | Ask a platform administrator to allow one of your groups. |
| `403 origin_not_allowed` | The request came from a browser page. | Use a desktop or CLI client. |
| `503 retry_later` / `unavailable` | The platform could not check the key or your permissions just now (`authz_unavailable`). It never defaults to allow. | Retry in a few seconds. |
| `503 mcp_disabled`: "MCP is switched off" | The server's own kill switch (operators). | Ask the platform team. |
| Tool error `insufficient_scope` | The key has chosen permissions that do not cover this tool. | Create a key with that permission, or with all your permissions. |
| Tool error `forbidden` | Your account lacks the permission. | Ask an administrator. |
| Tool error `never_via_mcp` | The action is never allowed through a key. | Do it in the console. |
| Tool error `protected_actions_off` | A protected write, and the key was created without protected actions. | Create a new key with protected actions allowed. |
| Tool error `use_apply_request` | Production: a key does not publish directly. | `request_site_apply`; a person approves it in the console. |
| Tool error `idempotency_key_reused` | The `idempotencyKey` was already used for a different change. | Omit it, or use a new one. |
| Tool error `rate_limited` | More than 60 reads a minute from this client. | Wait and retry. |
| No tools, or fewer than expected | The tool list follows your permissions. Calling a tool the key lacks answers `insufficient_scope` naming the permission. | Run `get_my_identity` and `get_my_permissions`, or read `docs://getting-started`. |

## Run

```bash
npm ci
cp .env.example .env          # TOKEN_VERIFIER=dev: fixed principal, NODE_ENV=development only
npm run dev                   # http://localhost:3100/mcp
npm test && npm run lint && npm run build
```

For local work against jinbe, run jinbe with `DEV_BYPASS_AUTH=true` and set `TOKEN_VERIFIER=dev`
here. Any bearer token is accepted and is mapped to `DEV_*`.

Container: `docker build -t auth-mcp .` (non-root, uid 1001, runs on a read-only root filesystem).
It listens on 3100 and serves `/healthz`.

## Deploy

The auth chart ships it (`charts/auth`, `mcp.enabled: true`, `mcp.host`, `mcp.image.tag`). The chart
also turns on, in jinbe, delegated tokens for the audience `https://<host>/mcp` from the actor
`<namespace>:auth-mcp`, and sets `MCP_PUBLIC_URL`, the address kuma shows until an administrator
saves another. jinbe's bootstrap writes the Oathkeeper rule `mcp`, which passes `/mcp` and
`/.well-known/oauth-protected-resource[/mcp]` through to auth-mcp without checking anything, because
auth-mcp checks every token itself.

The pod needs no Vault path and no Secret. Its only token is the projected ServiceAccount token,
with audience `jinbe`.

Images: `.github/workflows/build-image.yml` pushes `ghcr.io/w6d-io/auth-mcp:<branch>` and
`:sha-<short>` on every push (plus `:<version>` for a `v*` tag). Deploy the `sha-` tag.

## Config

Every setting, with its default, is in `src/config/env.ts`. The main ones:

| Variable | Meaning |
|---|---|
| `MCP_RESOURCE` | Public URL of `/mcp`. Also the token audience (RFC 8707) and the PRM `resource` |
| `HYDRA_ISSUER` | The authorization server advertised in the protected-resource metadata |
| `TOKEN_VERIFIER` | `jinbe` (default: jinbe introspects, hydra-admin stays closed), `hydra` (introspect at hydra-admin), `dev` |
| `JINBE_URL`, `ACTOR_TOKEN_PATH` | jinbe, and the projected ServiceAccount token (audience `jinbe`) sent as `X-Actor-Token` |
| `MCP_ENABLED`, `MCP_READ_ONLY`, `KILL_SWITCH_FILE` | Kill switches (see below). Read-only is the default |
| `RATE_READS_PER_MIN`, `RATE_WRITES_PER_MIN` | Per (user, client) budgets |
| `MCP_EXPOSE_UNWIRED_TOOLS` | List the W4 stubs (they always refuse) |

Kill-switch file (a mounted ConfigMap, re-read every 10 s; if it is malformed, MCP switches off):

```json
{ "enabled": true, "readOnly": false, "disabledOrgs": [], "disabledUsers": [],
  "disabledClients": [], "disabledKeys": [], "personalKeysDisabledOrgs": [] }
```

The file can switch MCP off or make it read-only. It can never switch back on something the
environment has switched off.

## Security model

- **Identity.** A request carries either an OAuth 2.1 access token (authorization code + PKCE via
  Hydra) or a personal key `stk_mcp_<id>.<secret>`. A personal key is exchanged for a 10-minute token
  and is never forwarded. Tokens must be active, carry audience `MCP_RESOURCE` and the `mcp` scope,
  and name a person (`ext.org`, when present, is informational only). When there is no token, or the token is bad,
  the server answers 401 with `WWW-Authenticate: Bearer resource_metadata=…` (RFC 9728, served at
  `/.well-known/oauth-protected-resource/mcp`).
- **No god credential.** Every call to jinbe carries the user's token (`Authorization`) *and* the
  pod's ServiceAccount token (`X-Actor-Token`). The first says who is calling and within which scopes.
  The second says the call came through auth-mcp. Neither works on its own. `X-Audit-Context: via=mcp;
  client_id=…; tool=…; key_id=…` is informational only.
- **auth-mcp only narrows.** Tools the token's scopes do not cover are hidden and refused. Wildcard
  scopes are ignored. Org-scoped tools take no org argument, because the org always comes from the
  token. Everything else is decided by jinbe → OPA.
- **Untrusted data.** Tool output goes into `structuredContent`, and into the text content inside an
  `<untrusted-data>` block whose `<`, `>` and `&` are escaped. Control, bidi and zero-width
  characters are stripped and strings are capped. Tool descriptions are static.
- **No secrets out.** A redaction filter runs on every result and every error before it leaves the
  server. It removes values under secret-named keys, plus token-, key-, PEM- and Vault-shaped strings.
  Person data is kept to the minimum: emails of who saved or applied something are dropped, and
  people lists carry only id, email, name and state.
- **Limits.** Each (user, client) pair gets a budget (60 reads and 10 writes per minute, in memory
  per replica). Responses are capped at 64 KB and flagged `truncated`. Request bodies are capped at
  256 KB. A browser `Origin` must be on the allow-list.
- **Writes.** Direct: a key does what its holder can do, and jinbe's delegation gate refuses what a
  key never may (403 `delegation_ineligible:*` → tool error `never_via_mcp`). Protected actions need a
  key created with them allowed (422 `step_up_unavailable` → `protected_actions_off`); production
  publishes answer `use_apply_request`. Every POST/PUT sends an `Idempotency-Key` (the caller's
  `idempotencyKey`, or a fresh one per call). auth-mcp never sends a DELETE except revoking the
  holder's own key, refuses `.`/`..` path segments, and refuses self-targeting locally too.

## jinbe endpoints used

- `POST /api/mcp/token-info`: introspection on auth-mcp's behalf (`TOKEN_VERIFIER=jinbe`).
- `POST /api/mcp/personal-keys/exchange`: exchanges a personal key for a 10-minute token.
- Every tool call: the user's token in `Authorization` together with `X-Actor-Token`.
- Writes: `/api/admin/sites/:name{,/draft,/diff,/apply,/rollback,/pause,/resume,/requests}`,
  `/api/admin/sites/:name/import/{preview,commit}`, `POST /api/admin/users`,
  `POST /api/admin/users/:id/{recovery-email,login-link}`, `PUT /api/admin/users/:email/groups`,
  `POST /api/admin/rbac/groups`, `PUT /api/admin/rbac/groups/:name`, `PUT /api/admin/rbac/services/:name/roles`,
  `DELETE /api/me/api-keys/:clientId`; and, from jinbe wave17/mcp-endpoints,
  `POST /api/admin/users/:id/{email,verification}`, `POST /api/admin/bulk/:op/{plan,execute}` and
  `GET /api/admin/bulk/jobs/:id`.

Each of them answers `403 {error: 'mcp_disabled'}` when an administrator has turned MCP off. auth-mcp
passes that on as 403 "MCP access is turned off by an administrator", not as a 401.
