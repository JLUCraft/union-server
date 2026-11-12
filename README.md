# Federated Server

The JLUCraft service host for authority nodes, Minecraft connections, scoring, activity delivery, organization workflows, and AI workers.

The centralization program moves account and game authority to the skin station.
The Yggdrasil session profile is already generated at build time from
`../federated-skinstation/shared/contracts/session-profile.schema.json` using
`typify`, and the textures client consumes that generated type. Keep the skin
station checkout available when building. The native TCP gateway uses encrypted
Minecraft login and Yggdrasil `hasJoined`. Remaining federation host services
are removed in subsequent centralization batches.

Scoring now uses the skin station's league service. The local Paper adapter
exposes `GET /v1/session/:id`, `POST /v1/score`, and `POST /v1/finish`.
Its session response contains the central competition in `league` and current
Minecraft UUID lists keyed by account ID in `profiles`. Score keys are account
IDs. The skin station checks the designated scorer, club membership, replay
payloads, and competition state on every operation.

Configure `services.scoring` with `bind`, `skin_site`, `session_token`, and
`token`. `bind` must be loopback; `skin_site` is a bare HTTPS origin, with HTTP
allowed for loopback development. The two credential paths resolve relative to
the host configuration file. `session_token` contains a Yggdrasil session for
the scorer account and is read on every request so it can be replaced after
renewal. `token` contains the separate 32–256 character Paper bearer loaded at
startup. Keep both files outside the repository with owner-only permissions.
Scoring no longer needs a device key, identity log, or governance journal.
The host's remaining federation services are removed in subsequent batches;
operations M1–M6 stay frozen.

## Native Minecraft gateway

`services.league_proxy.config` configures a standalone TCP listener. It uses a
Yggdrasil session for the league's designated host account; the credential file
is read on every central request. It does not publish a federation game service
or require an identity/governance service. The current host assembly still
requires its node configuration for the remaining services.

```json
{
  "league": "cup",
  "bind": "0.0.0.0:25565",
  "transfer": { "host": "game.example.test", "port": 25565 },
  "skin_site": "https://skin.jlucraft.com",
  "session_token": "host.session",
  "waiting": { "address": "127.0.0.1:25566", "forwarding_secret": "waiting.secret" },
  "arena": { "address": "127.0.0.1:25567", "forwarding_secret": "arena.secret" }
}
```

Paths resolve relative to the host configuration file. Keep that configuration
and all credentials outside the repository, with secret files accessible only
to their owner. Both Paper servers must bind loopback and enable their built-in
Velocity identity forwarding with their respective secrets.

Players connect directly to the configured TCP address. The gateway performs
RSA challenge verification and AES-128-CFB8 encryption, authenticates the
claimed profile through the skin station, and forwards its canonical identity
and validated textures with the TCP client address to Paper. Admission maps the current UUID to its central
account. Connections are unique per account, including extra profiles.
Candidate rooms and seat epochs come from current central admission; explicit
transfer configuration supplies the public reconnect target. Backend status,
presence, infrastructure changes, and expiry ticks use the central league API.

Set `league` to `auto` to follow the host account's assigned competitions. Exactly
one playing assignment opens the route; zero or multiple assignments close it.
Assignment changes close the previous connections before serving the new game.

Active admission is refreshed each second. Connections close when an admission
request fails or the last accepted decision is ten seconds old. Routing updates
transfer clients between waiting and arena rooms, including seat replacement
and pause changes. This path no longer feeds the federation activity oracle;
central activity delivery is the following consumer migration.

## Setup and structure

Keep sibling `union-core` and `minecraftd` checkouts available. The production entry is `federated-server`; initialization and signed host registration use its subcommands. Configuration is defined by the Rust types and command parser in `src/`. The workspace includes `game/league`, retaining the `league` crate name and its league API. Its `events` module combines office records with game state; `application`, `points`, `discovery`, `files`, and `trust` provide game clients. Game integration tests reuse the generic fixture in `../union-core/tests/support/mod.rs`. Production keys and founder authorization stay outside the repository.

Workflow composition requires an explicit `flows::Workflow` implementation in
addition to `state::Domain`. `EventsDomain` implements the workflow hooks for
points, AI allowances and documents, review material, worker selection, club
approvals, and artifact-backed transitions. `Domain` retains its state and action
types and its transition; `LeagueDomain` continues to implement only
`Domain`. Hooks omitted from a `Workflow` implementation use the library defaults.
The host's `AiDomain` and `NotificationDomain` traits both extend `Workflow` and
add their file-storage and notification capabilities without redefining its hooks.

## Identity bindings and sessions

Game profiles use the generic identity action `BindAttribute { member, club,
kind, value }`, with `league::GAME_PROFILE` as the kind and verifier evidence.
`UnbindAttribute { member, kind }` removes the binding. The identity library
checks membership, signatures, verifier authority, and value uniqueness within
each kind. A bind requires the member's signature plus the club chair or an
active verifier authorized for that kind; unbinding requires the member or
recovery authorization. `league::validate_game_profile` defines the game format:
exactly 32 lowercase hexadecimal digits, without UUID separators. The identity
bridge accepts only this kind and valid values for its configured club; its
membership evidence remains `institutional_email`.

The host selects `node::attribute_session(league::GAME_PROFILE)`. Trusted game
sessions require the binding and close when it changes or is removed; other
identity checks still apply. Admission claims carry `TrustAdmission.attributes`.
Native and room connections validate the game attribute and compare it with the
actual Minecraft login UUID before forwarding. Scoring exposes only valid game
profiles, and activity processing checks the same attribute against witnessed
play. Format validation belongs to these game consumers; the identity core accepts
generic attribute values. Existing signed identity logs require a separate
migration to the new action schema.

## Protocol namespace

The required `node.namespace` object configures transport, discovery, service
protocols, MCP service names and headers, and signature verification. Missing
namespace configuration is rejected. JLUCraft deployments use:

```json
{"node":{"key":"node.key","namespace":{"organization":"jlucraft","version":1}}}
```

`version` is an input alias for `wire_version`. The canonical namespace contains
`organization`, `wire_version`, and `signing_version`; only `signing_version`
defaults to 1. Organizations contain 1–64 lowercase ASCII letters, digits, or
hyphens; both versions must be positive. Wire versions change protocols and KAD
keys independently of signature domains. The explicit JLUCraft namespace
preserves all original protocol, KAD, and signature-domain bytes.

The identity genesis contains the namespace instead of a separate federation
string, and its digest covers every namespace field. The host namespace must
match the supplied genesis organization and signing version. The runtime wire
version may change without editing genesis or replacing its pin. The schema
change requires reviewing and distributing new genesis pins; it does not migrate existing identity or governance logs.
The MCP relay and workflow clients inherit the host namespace. A custom
organization selects `x-<organization>-envelope` and `<organization>-control`.
The standalone identity bridge also requires an explicit namespace. Exported
identity client settings always include it. `jlucraft-agent` accepts
`--organization` and `--protocol-version`; its default organization comes from
the compile-time variable `UNION_ORGANIZATION` (default: `jlucraft`), with wire
and signing versions defaulting to 1. Signing version remains 1 when the wire
version changes. FollyLauncher must be built with `UNION_ORGANIZATION` matching
this server's configured `node.namespace.organization`; otherwise, handshake
protocol names will not match. Acceptance terminal node arguments require both
namespace flags.

## Network operations

League discovery exposes `Discovered::to_json()` for terminal adapters. Its `services` array contains objects with `id`, `name`, and `protocol`; service metadata is omitted.

The `services.operations` service manages the locally configured Minecraft instances. In addition to lifecycle and recent-output operations, its request schema exposes capabilities, host/instance metrics, single-line game console commands, paginated jobs and audit records, and backup creation, verification, restoration, listing, and deletion. The schema is defined only in `union-core/crates/protocol/src/lib.rs`.

```json
{
  "service": "11111111-1111-4111-8111-111111111111",
  "instances": [],
  "state": "operations-jobs.json",
  "audit": "operations-audit.jsonl",
  "archives": {
    "base_dir": "archives",
    "algorithm": "Zip",
    "default_scope": "Full",
    "max_archives_per_instance": 10,
    "auto_cleanup": true
  }
}
```

Relative paths are resolved from the host configuration directory. Archive and instance directories must be disjoint. The job store is written atomically; unfinished jobs are marked failed after a host restart instead of silently resumed. Audit records are append-only JSONL with a bounded in-memory query history and an MVP file-size limit.

The `manage` permission authorizes every operation. Deployments can instead grant `read`, `logs`, `operate`, `console`, `backup`, or `restore` independently. Authorization is checked again for every request using the authenticated device and current identity view.

Delegated operations additionally require the session peer to hold `mcp_relay`;
`manage` alone does not grant relay access. The service verifies the signed
caller, time, host/service/gateway/tool audience, request digest, shared tool
mapping, and a service-local nonce cache before authorizing the signer for the
operation. Signature, time, audience, and relay authorization failures return
`permission_denied`; digest or mapping mismatches return `invalid_request`;
replays return `conflict`; an exhausted or unavailable nonce cache returns `busy`.
Mutation audits identify the signer as `actor` and include `relay` and `nonce`.
Idempotent job digests exclude delegation so existing jobs remain reusable.

Backup and restore submissions require an idempotency key and return a job ID. Backups are created while the instance is stopped and are verified before completion. Restore creates a safety archive, extracts into a sibling staging directory, swaps directories, and restores the original directory if the restored instance cannot start. Console commands are limited to one line and go only to the Minecraft process stdin, never to a host shell. Command responses contain output appended after the command, bounded by a short collection timeout; an empty result means no new output. Global line indices exclude earlier output even when the recent window rolls over. Replies contain at most 100 captured lines; if newer output has already been evicted from that window, a notice reports the number of dropped lines before the available output. All built instances initialize bounded process-output buffering.

## MCP adapter

Set `services.mcp` to expose the control-plane services through the Model Context Protocol over Streamable HTTP at `POST /mcp`. The adapter is optional and disabled by default and is a peer of the manager app: it consumes operations, governance journals, and identity services through one relay node.

```json
{
  "bind": "127.0.0.1:9090",
  "relay_key": "relay.key",
  "operations": [
    {
      "name": "ops",
      "peer": "<operations-host-peer>",
      "address": "/ip4/127.0.0.1/udp/40000/quic-v1",
      "service": "11111111-1111-4111-8111-111111111111"
    }
  ],
  "principals": [
    {
      "name": "alice",
      "peer": "<alice-peer>",
      "operations": ["ops"],
      "identity": { "peer": "<identity-host-peer>", "address": "/ip4/127.0.0.1/udp/40000/quic-v1" },
      "application": {
        "peer": "<governance-host-peer>",
        "address": "/ip4/127.0.0.1/udp/40000/quic-v1",
        "genesis_hash": "<pinned-governance-genesis-sha256>"
      }
    }
  ]
}
```

The gateway loads only `relay_key` and starts one relay node. Each principal registers a distinct caller `peer`, an `operations` endpoint allowlist, an optional `identity` endpoint for genesis, history, and record submission, and an optional `application` endpoint with a pinned governance genesis hash. An application endpoint requires an identity endpoint; its identity genesis pin comes from the verified governance snapshot binding. Principal peers must be valid, unique, and different from the relay peer. At most one operations endpoint may be assigned to each principal. Paths are relative to the host configuration file. Caller private keys stay with callers; the gateway has no caller key, token, or trust-file setting.

Every request supplies `X-JLUCraft-Envelope`, an unpadded base64url encoding of the signed `McpEnvelope` JSON. The encoded header is limited to 4 KiB and the request body to 8 MiB. The signature binds the caller's Ed25519 public key and peer, audience, issue/expiry times, nonce, and canonical request digest. The shared `identity::mcp_envelope::canonical_request(method, arguments)` helper recursively sorts JSON keys and builds `{"method": method, "params": {"arguments": arguments}}`, omitting `arguments` when absent. For `tools/call`, the method is the tool name and arguments come from the original `params.arguments`; for other RPC methods, arguments are the original params. The gateway removes `params._meta` first; nested `_meta` keys remain signed. Omitted arguments and explicit `{}` have distinct digests. Hashing rejects floating-point parameters and batches. RPC IDs are outside the digest.

`aud.gateway` always names the relay peer. For operations calls, `aud.peer` and `aud.service` name the configured operations host and service, and `aud.tool` is the tool name. For `initialize`, `tools/list`, `ping`, and `notifications/initialized`, use the relay peer, service `gateway`, and the method name. For `identity_*`, use the relay peer, service `gateway`, and the tool name. For `application_*`, use the configured governance peer, the journal protocol `/jlucraft/union/application/1`, and the tool name. The middleware reads the tool name from the request body before selecting the expected audience. The gateway independently verifies every request and places the verified principal, original envelope, and digest in the request context. It forwards the original caller signature and optional canonical arguments to operations through the relay node. Operations verifies the same canonical request before treating absent arguments as `{}` for tool mapping. Grant the relay device `mcp_relay` on that operations service; the caller still needs its own operation permission. The operations service verifies delegation and uses the signer for authorization and audit.

Envelope lifetime is at most 60 seconds. The gateway allows 30 seconds of clock drift and retains each signer/nonce through `exp_ms + 30 seconds`, including that boundary. Its replay cache holds 65,536 entries, never evicts a live nonce, and is independent of the operations service cache. A fresh nonce is required for each HTTP attempt, including retries. Cache state is in memory; restarting the gateway clears it, so an unexpired envelope may be accepted again after restart. Keep clocks synchronized.

Missing or malformed headers and malformed JSON return HTTP 400. Invalid signatures, time claims, request digests, and replayed nonces return 401. Unregistered signers, audience mismatches, and disallowed tools or operations targets return 403. Oversized headers or bodies return 413; replay-cache exhaustion or unavailability returns 503. Business failures remain tool results with their structured operations errors.

The catalog has 26 tools: 20 `ops_*`, 2 `application_*`, and 4 `identity_*`. Operations cover capabilities, instance lifecycle, league start and stop, metrics, logs, commands, jobs, audit, and backups. Backup jobs require caller-supplied idempotency keys and can be queried with `ops_get_job`. `identity_public` returns the envelope signer's peer and public key in the existing response format; `identity_genesis` fetches genesis through the relay node, and `identity_review` verifies supplied history. `identity_submit` accepts the signed `TrustRecord` JSON directly as its arguments and relays `TrustRequest::Append`; the identity authority validates the record signatures independently of the transport identity. The agent drafts and signs the record locally against its own trusted log; there is no `identity_draft` tool.

`application_snapshot` requires explicit `{}` arguments and returns `snapshot`, `identity_checkpoint`, `peer`, and `protocol`. `snapshot` is the verified authority response, including the governance genesis hash, head, revision, and journal identity anchor. `identity_checkpoint` is the current checkpoint obtained by replaying the configured identity service against the snapshot's identity genesis pin; it can be ahead of the journal anchor. The agent uses this context to sign a `TrustedCommand` locally and sets its envelope audience from `peer` and `protocol` with the relay as `aud.gateway`.

`application_submit` accepts `{"command":{"payload":"<b64pad>","public_key":"<b64pad>","signature":"<b64pad>"}}`. All three fields use canonical standard padded base64. The agent signs both the command and its request envelope locally. The gateway reads the governance identity anchor, fills missing verified history through `client::trust::history_since`, and relays `Request::Execute` with the original envelope as `Exchange.delegation`. The authority response is returned unchanged, with authority failures marked as tool errors. The relay needs service-scoped `mcp_relay` permission and `read` permission for the preparatory snapshot; the caller still needs its own governance permissions. Concurrent head or identity changes require the agent to fetch a fresh snapshot and sign again with a fresh nonce.

Set `allowed_hosts` and, for browser clients, `allowed_origins` when connecting through a LAN name or reverse proxy; the library default accepts loopback hosts only. Keep the relay key outside the repository with owner-only permissions and use a TLS reverse proxy for remote clients.

## Validation

Select one validation channel for a batch and reuse successful results for unchanged inputs. Standard commands:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
FOUNDER_MANIFEST="$PWD/tests/fixtures/founders.json" cargo test --locked -- --test-threads=1
```

Read [AGENTS.md](AGENTS.md) before making changes.

## Local agent signing

Build the second binary with `cargo build --locked --bin jlucraft-agent`. Keep the
identity key on the agent's machine, outside the repository and service host.

```sh
jlucraft-agent keygen --out /absolute/private/path/agent.key
jlucraft-agent public --key /absolute/private/path/agent.key
jlucraft-agent sign-command --key /absolute/private/path/agent.key --input command.json
jlucraft-agent sign-record --key /absolute/private/path/agent.key --input - < record.json
```

`keygen` creates an Ed25519 key in the existing protobuf key format, with mode
0600 on Unix, and refuses to overwrite an existing path. On Windows, use a
directory protected by the user's ACL. Both `keygen` and `public` return
`{"peer":"<peer-id>","public_key":"<base64pad>"}`; the public key is protobuf-encoded.
Private key material is written only to the key file.

Both signing commands accept a JSON file path, an inline JSON object, or `-` for
stdin. `sign-command` reads `TrustedCommand<league::application::Application>`
with `genesis`, `previous`, `identity`, and `command` fields. Use the trusted
snapshot's genesis hash, journal head, identity checkpoint, and revision; set
`command.expires_ms` and `command.action` before signing. Its output contains
`payload`, `public_key`, and `signature`, all in standard padded base64. Supply
this object as `application_submit`'s `command` argument.

`sign-record` reads a `TrustRecord` and adds the local signature while retaining
existing signatures. Its output uses the identity log's original JSON format,
including byte arrays in `signatures`, and can be sent directly as
`identity_submit` arguments or as the `record` in `TrustRequest::Append`.
Duplicate signatures from the same key are rejected. Review the record against
your trusted identity history before signing; signing alone does not establish
authorization or freshness. Request envelopes are signed separately.

Successful operations write one JSON object to stdout. Failures exit nonzero
with diagnostics on stderr and no JSON output.

## Reusing the MCP gateway

The MCP adapter enables the `forwarding` feature of `federation-mcp` from
`union-core/crates/mcp`. The default library provides envelope verification,
canonical commitments, header codecs, and replay protection with only `protocol`
and `identity` as platform dependencies. Its optional `mcp::forwarding` module
adds `node` and `client` for delegated operations and journal forwarding.

Each `mcp::Principal` holds its own `Audience` policy. This server's
`HostAudience` resolves its endpoint allowlist and local/journal service names;
`HostToolMapping` injects the existing operations and application mappings.
`mcp::forwarding::Gateway::new` takes the configuration, relay node, and mapping.
The server selects the existing clock tolerance and retains its rmcp
catalog, identity history synchronization, and application response presentation.
The existing 20 operations, 2 application, and 4 identity tools, envelope
audiences, and HTTP error statuses are preserved.
