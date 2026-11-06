# Federated Server

The JLUCraft service host for authority nodes, Minecraft connections, scoring, activity delivery, organization workflows, and AI workers.

## Setup and structure

Keep sibling `union-core` and `minecraftd` checkouts available. The production entry is `federated-server`; initialization and signed host registration use its subcommands. Configuration is defined by the Rust types and command parser in `src/`. Production keys and founder authorization stay outside the repository.

## Network operations

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

Backup and restore submissions require an idempotency key and return a job ID. Backups are created while the instance is stopped and are verified before completion. Restore creates a safety archive, extracts into a sibling staging directory, swaps directories, and restores the original directory if the restored instance cannot start. Console commands are limited to one line and go only to the Minecraft process stdin, never to a host shell. Command responses contain output appended after the command, bounded by a short collection timeout; an empty result means no new output. All built instances initialize bounded process-output buffering.

## MCP adapter

Set `services.mcp` to expose the control-plane services through the Model Context Protocol over Streamable HTTP at `POST /mcp`. The adapter is optional and disabled by default and is a peer of the manager app: it consumes the same operations service and the same organization-application journal.

```json
{
  "bind": "127.0.0.1:9090",
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
      "key": "alice.key",
      "token": "alice.token",
      "operations": ["ops"],
      "trust": "alice-trust.json",
      "identity": { "peer": "<identity-host-peer>", "address": "/ip4/127.0.0.1/udp/40000/quic-v1" }
    }
  ]
}
```

Each principal is a distinct caller: `token` is its Bearer secret, `key` is its signing identity, `operations` lists the operations endpoints it may use, `trust` supplies the per-caller trust configuration for organization-application requests, and `identity` is the optional identity service used for read-only genesis retrieval. Every tool call is signed by that principal's key, so server-side authorization and audit stay per caller; there is no shared executor. Set `allowed_hosts` (and `allowed_origins` if browsers connect directly) when the listener is reached through a LAN name or a reverse proxy; the library default accepts loopback hosts only. Keep key, token and trust files outside the repository with owner-only permissions. Use a TLS reverse proxy for remote clients; do not expose the plain HTTP listener directly to an untrusted network.

The catalog contains three groups. `ops_*` covers capabilities, instance lifecycle, metrics, recent logs, game commands, jobs, audit, and backups. `application_*` reads the application snapshot and submits league creation, event creation and amendment, flow approval and rejection, file upload, and AI point requests through the same dispatcher the manager app uses. `identity_*` exposes the caller's public identity, its pinned genesis, and history review. Tool arguments use strict schemas; a caller without the matching endpoint, trust configuration, or identity endpoint receives a clear tool error. Backup jobs require caller-supplied idempotency keys and return structured job data for `ops_get_job`. Tool-level failures preserve the operations error object instead of collapsing into an MCP transport error.

## Validation

Select one validation channel for a batch and reuse successful results for unchanged inputs. Standard commands:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Read [AGENTS.md](AGENTS.md) before making changes.
