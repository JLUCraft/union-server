# Federated Server

The JLUCraft service host for authority nodes, Minecraft connections, scoring, activity delivery, organization workflows, and AI workers.

## Setup and structure

Keep sibling `union-core` and `minecraftd` checkouts available. The production entry is `federated-server`; initialization and signed host registration use its subcommands. Configuration is defined by the Rust types and command parser in `src/`. The workspace includes `game/league`, retaining the `league` crate name and its league API. Its `events` module combines office records with game state; `application`, `points`, `discovery`, `files`, and `trust` provide game clients. Game integration tests reuse the generic fixture in `../union-core/tests/support/mod.rs`. Production keys and founder authorization stay outside the repository.

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

Backup and restore submissions require an idempotency key and return a job ID. Backups are created while the instance is stopped and are verified before completion. Restore creates a safety archive, extracts into a sibling staging directory, swaps directories, and restores the original directory if the restored instance cannot start. Console commands are limited to one line and go only to the Minecraft process stdin, never to a host shell. Command responses contain output appended after the command, bounded by a short collection timeout; an empty result means no new output. All built instances initialize bounded process-output buffering.

## MCP adapter

Set `services.mcp` to expose the control-plane services through the Model Context Protocol over Streamable HTTP at `POST /mcp`. The adapter is optional and disabled by default and is a peer of the manager app: it consumes the operations and read-only identity services. Application tools are temporarily unavailable pending delegation support.

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
      "identity": { "peer": "<identity-host-peer>", "address": "/ip4/127.0.0.1/udp/40000/quic-v1" }
    }
  ]
}
```

The gateway loads only `relay_key` and starts one relay node. Each principal registers a distinct caller `peer`, an `operations` endpoint allowlist, and an optional `identity` endpoint for genesis retrieval. Principal peers must be valid, unique, and different from the relay peer. At most one operations endpoint may be assigned to each principal. Paths are relative to the host configuration file. Caller private keys stay with callers; the gateway has no caller key, token, or trust-file setting.

Every request supplies `X-JLUCraft-Envelope`, an unpadded base64url encoding of the signed `McpEnvelope` JSON. The encoded header is limited to 4 KiB and the request body to 8 MiB. The signature binds the caller's Ed25519 public key and peer, audience, issue/expiry times, nonce, and canonical request digest. The shared `identity::mcp_envelope::canonical_request(method, arguments)` helper recursively sorts JSON keys and builds `{"method": method, "params": {"arguments": arguments}}`, omitting `arguments` when absent. For `tools/call`, the method is the tool name and arguments come from the original `params.arguments`; for other RPC methods, arguments are the original params. The gateway removes `params._meta` first; nested `_meta` keys remain signed. Omitted arguments and explicit `{}` have distinct digests. Hashing rejects floating-point parameters and batches. RPC IDs are outside the digest.

`aud.gateway` always names the relay peer. For operations calls, `aud.peer` and `aud.service` name the configured operations host and service, and `aud.tool` is the tool name. For `initialize`, `tools/list`, `ping`, and `notifications/initialized`, use the relay peer, service `gateway`, and the method name. For `identity_*` and the currently unavailable `application_*` tools, use the relay peer, service `gateway`, and the tool name. The gateway independently verifies every request and places the verified principal, original envelope, and digest in the request context. It forwards the original caller signature and optional canonical arguments to operations through the relay node. Operations verifies the same canonical request before treating absent arguments as `{}` for tool mapping. Grant the relay device `mcp_relay` on that operations service; the caller still needs its own operation permission. The operations service verifies delegation and uses the signer for authorization and audit.

Envelope lifetime is at most 60 seconds. The gateway allows 30 seconds of clock drift and retains each signer/nonce through `exp_ms + 30 seconds`, including that boundary. Its replay cache holds 65,536 entries, never evicts a live nonce, and is independent of the operations service cache. A fresh nonce is required for each HTTP attempt, including retries. Cache state is in memory; restarting the gateway clears it, so an unexpired envelope may be accepted again after restart. Keep clocks synchronized.

Missing or malformed headers and malformed JSON return HTTP 400. Invalid signatures, time claims, request digests, and replayed nonces return 401. Unregistered signers, audience mismatches, and disallowed tools or operations targets return 403. Oversized headers or bodies return 413; replay-cache exhaustion or unavailability returns 503. Business failures remain tool results with their structured operations errors.

The catalog keeps 32 tools: 20 `ops_*`, 9 `application_*`, and 3 `identity_*`. Operations cover capabilities, instance lifecycle, league start and stop, metrics, logs, commands, jobs, audit, and backups. Backup jobs require caller-supplied idempotency keys and can be queried with `ops_get_job`. `identity_public` returns the envelope signer's peer and public key in the existing response format; `identity_genesis` fetches genesis through the relay node, and `identity_review` verifies supplied history. Every `application_*` call currently returns an explicit unavailable tool error pointing to future application delegation support: the gateway no longer holds caller private keys and cannot sign application actions. The tool schemas remain available for discovery.

Set `allowed_hosts` and, for browser clients, `allowed_origins` when connecting through a LAN name or reverse proxy; the library default accepts loopback hosts only. Keep the relay key outside the repository with owner-only permissions and use a TLS reverse proxy for remote clients.

## Validation

Select one validation channel for a batch and reuse successful results for unchanged inputs. Standard commands:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
FOUNDER_MANIFEST="$PWD/tests/fixtures/founders.json" cargo test --locked -- --test-threads=1
```

Read [AGENTS.md](AGENTS.md) before making changes.
