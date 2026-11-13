# Federated Server

The JLUCraft central Minecraft game host: encrypted native connections, Paper
scoring, and measured activity delivery through the skin station.

The skin station owns accounts, permissions, league state, organization workflows,
AI jobs, and points. This host consumes generated central contracts. Keep the
sibling `federated-skinstation` checkout available when building.

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
Central operations use a separate supervisor process controlled through the skin station MCP.

## Native Minecraft gateway

`services.league_proxy.config` configures a standalone TCP listener. It uses a
Yggdrasil session for the league's designated host account; the credential file
is read on every central request. It does not publish a federation game service
or require a federation node. Start the waiting and arena Paper processes
separately before using the gateway.

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
and pause changes. Arena play records activity witnesses with the authenticated
account, UUID, and centrally assigned resource. Configuration, waiting, and
closed connections do not supply continuous-play evidence.

## Activity delivery

The Paper adapter accepts `POST /v1/activity/:source/slice` and
`POST /v1/activity/:source/flush` on loopback. Configure `services.activity_oracle`
with `bind`, `skin_site`, `session_token`, `spool`, and `probes`. Each probe has
`source`, `resource`, and `token`; resource IDs come from the central game resource.
Credential and spool paths resolve relative to the host configuration file.
Keep credentials and the owner-only spool outside the repository. The session
file contains the central host account's Yggdrasil session and is reread for
requests; each Paper token is loaded at startup.

Current source assignments come from `GET /api/hosted-activity-sources`.
Only native gateway play that covers the entire five-minute slice, with client
traffic during its final minute, supplies an account/UUID witness. Multiple
profiles cannot credit an account twice in a slice. Look variation and at least
two movement, interaction, or progress dimensions determine active versus AFK
slices. Unwitnessed telemetry remains in the private proof without credits.

Reports aggregate for up to thirty minutes, with earlier delivery on gaps,
proof limits, explicit flush, or shutdown. Acknowledgments follow durable spool
writes. The exact request is frozen on disk before central delivery; uncertain
responses and restarts resend that request to the atomic central endpoint.
Completed requests support one day of exact report retries.
The skin station owns private evidence, current profile ownership checks, and
point accounting. `GET /v1/activity/:source/evidence/:id` exposes only that
source's retained central artifact through its Paper bearer.

The adapter starts independently of governance and shares native gateway
witnesses. Central delivery types and limits are generated from the skin
station's points and office contracts.

## Setup and operations

Build and run from this repository with the skin station checkout beside it:

```sh
cargo build --locked
cargo run --locked -- check --config /absolute/private/path/host.json
cargo run --locked -- run --config /absolute/private/path/host.json
```

The configuration contains a `services` object with `league_proxy`, `scoring`,
and `activity_oracle`; enable the services needed by this host. `league_proxy`
contains the `config` object shown above. Other adapters take their fields
directly. At least one service must be configured. Example for a scoring host:

```json
{
  "services": {
    "scoring": {
      "bind": "127.0.0.1:4238",
      "skin_site": "https://skin.jlucraft.com",
      "session_token": "host.session",
      "token": "paper.token"
    }
  }
}
```

Startup prints one JSON object listing the actual listener addresses by service.
A service failure stops supervision with an error. Ctrl+C or SIGTERM requests
shutdown: the gateway closes connections and reports infrastructure down,
HTTP adapters finish active requests, and activity evidence is flushed from the
spool. Explicit `Host::close` awaits shutdown. Dropping a host requests shutdown
asynchronously. Startup failure closes services already opened before returning.

## Central operations supervisor

Run the executor as a separate process so it remains available when the managed
game host stops:

```sh
federated-server supervise --config /srv/jlucraft/supervisor.json
```

```json
{
  "bind": "127.0.0.1:26010",
  "data": "/srv/jlucraft/managed",
  "credential_file": "/srv/jlucraft/ops.credential",
  "host": "campus",
  "authority": "https://skin.jlucraft.com",
  "backups": {
    "retained": 10,
    "retained_bytes": 107374182400,
    "archive_bytes": 10737418240,
    "entries": 100000,
    "remote": null
  },
  "artifact_origins": ["https://artifacts.example.org"],
  "profiles": {
    "gateway": {
      "start_command": "bin/federated-server run --config host.json",
      "stop_command": "",
      "kind": "service",
      "readiness": {
        "output": "\"services\":",
        "timeout_seconds": 60,
        "stabilize_seconds": 5
      }
    }
  }
}
```

Kinds are `java`, `bedrock`, and `service`. Profiles define operator-controlled
commands and readiness output. Set `readiness.output` to the service's startup
message; the gateway example uses its emitted service status JSON. Set
`readiness` to null for lifecycle-only profiles. Instance definitions persist
inside `data/instances/<id>` and are loaded when the supervisor restarts. The
executor accepts start, stop, and restart jobs from the central service; it does
not expose a shell or accept game session credentials. Empty stop commands use
SIGTERM on Unix, and `^C` uses SIGINT. Processes stop before lifecycle completion.

Store the 32-byte hexadecimal credential outside the repository in a regular
file with mode 0600. Configure its matching value in the skin station's private
environment. Keep the loopback executor behind an HTTPS reverse proxy when the
skin station runs remotely. The skin station checks account identity, OAuth
scope, and the instance's central permission binding. A site administrator assigns
each instance to the appropriate club or global scope.

`host` identifies this executor in the skin station's operations configuration.
`authority` is the skin station origin. Before starting each queued job, the
executor authenticates to its private claim route with the same host credential.
The central service rechecks the saved request's live authorization and any
required human confirmation. A claim failure leaves the job failed without
executing its command. Forced termination is bound to the approved instance PID.

The supervisor owns a data-directory lock and a SQLite job journal. Duplicate
job IDs preserve the original request, and a different payload under the same
ID is rejected. Jobs retain administrator/client/call attribution. A lease must
remain valid when queued work starts. A queued retry renews the stored lease;
execution admission reads that lease in the same transaction as the state change.
Interrupted jobs remain marked after a restart and require a new administrator
decision. Shutdown retains the ownership lock and retries failed instance cleanup
until all managed processes have been released. Run the supervisor under a
system service with `Restart=on-failure` and `KillMode=control-group` so a process
failure releases its managed process group before restart.

The executor persists console output with monotonic resume cursors, retaining the
latest 512 segments per instance. Output enters a bounded capture queue and
is committed in batches outside the async workers. Queue overflow records a
capture gap, and shutdown drains accepted output before releasing ownership. Responses stay within the central contract byte
limit and report retention gaps or clipped segments. Console input is enabled for
game instances and disabled for generic services. Queued jobs can be canceled;
running commands keep their recorded execution state.

Instance observations collect process memory, CPU samples, and storage space on
request. CPU remains absent until a second sample is available. Alerts identify
unexpected stops, process errors, lost log capture, and storage or memory with
less than ten percent free capacity.

Historical operations code in `src/ops.rs`, `src/ops_extended.rs`, and
`src/rooms.rs` remains excluded from the build. The active execution path uses
minecraftd and generated skin-station contracts.

Project development rules are in `AGENTS.md`. Standard validation:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Central lifecycle stop and restart use graceful termination. A timeout fails the job and preserves the managed process. Force termination uses the human-approved PID-bound kill action.

The Linux supervisor supports `backup`, `restore_prepare`, `restore`,
`backup_export`, `backup_import`, and `backup_delete` jobs. `backup` takes a
`label`, stops the instance gracefully, archives the complete instance directory,
and resumes an instance that was running. A failed or unclean stop prevents the
archive. Keep all managed service data inside its instance directory. Limits
bound archive bytes, expanded bytes, entry count, retained count, and retained
compressed bytes per instance. Retention keeps the newly published archive.
`GET /api/operations/hosts/<host>/instances/<instance>/backups` lists the caller's
scoped archives through the skin station MCP. Completed jobs include their backup
receipt.

Run `restore_prepare` with an `archive` ID before requesting restoration. It
extracts the candidate while the instance remains available. Its job ID identifies
the preparation. Submit `restore` with `archive` and `preparation`; a human
confirms that exact request in the skin station. Starting, stopping, restarting, commanding, or
backing up the instance discards its preparation. Activation swaps the directories
atomically. A durable journal restores the previous directory after an interrupted
activation. Fresh authorization admits the restore transaction before it stops the
instance. The admitted transaction saves the current safety archive, activates the
candidate, and resumes an instance that was running. It completes without calling
the authority while that managed service is stopped. The completed job returns
`safetyArchive`.
Use the same preparation and confirmation flow with a safety archive to roll back.
Deleting a backup requires human confirmation.

For encrypted off-host recovery, set `backups.remote` to an object with `endpoint`,
`credential_file`, `recipient`, and optional `identity_file`. The endpoint is an
HTTPS origin serving atomic authenticated `PUT` and `GET` at
`/backups/<archive-id>.age`; numeric loopback HTTP supports local deployments.
The credential file supplies the bearer credential. `recipient` is the public age
X25519 recipient. Keep its private age identity offline; install its secret string
in `identity_file` only when importing a recovery archive. Secret files require
mode 0600 outside the repository. Export streams authenticated encryption before
upload; import consumes the authenticated stream before publishing data and checks
the instance and permission scope. Record archive IDs outside the host and set the
remote store's retention and storage limits. Import restores the archive to the
local catalog; preparation and human confirmation apply before replacing data.

Reserve an instance through `POST /api/operations/hosts/<host>/instances` with
`scope` and an idempotency `key`. Global administrators receive a server-generated
instance ID and central permission binding. Submit a `provision` job for that ID
with `profile`, `autoStart`, and `changes`. Provisioning requires scope management
permission, global management permission, and fresh human confirmation. Each change has a relative `path` and one of `text`, `url`, or
`remove: true`. Text and downloaded files accept `executable: true` for service
binaries. Files are private by default. Artifact URLs must use an origin in
`artifact_origins`; redirects are rejected. Byte and entry limits reuse the
configured archive quotas. Put server binaries, configuration, mods, and plugins
inside the managed instance directory. Operator profiles supply the commands.

Use `deploy_prepare` with `changes` to download and stage an update while the
service remains running. Preparation and activation require global management
permission. Submit `deploy` with the preparation job ID and confirm that request
in the skin station. The confirmation displays the staged changes from their
recorded request. The admitted transaction stops the service,
saves its current recovery archive, applies staged changes to a fresh candidate,
and switches directories atomically. Readiness uses captured process output and
a configured period of continued process life. A failed start or readiness
deadline restores the previous directory and running state. If graceful shutdown
fails, the supervisor retains process ownership and the recovery journal; resolve
the process through the existing confirmed kill action before restarting the
supervisor. A successful job returns `safetyArchive` for later rollback. A service
that was stopped is started for readiness and stopped again before completion.
Profiles with readiness settings also check restored services before committing.

`instance_delete` saves a recovery archive, removes the stopped instance, and
returns its archive ID. Deployment activation and deletion require scope
management permission and fresh human confirmation. Recovery after host loss
uses the same host identity and central instance binding: configure its profiles
and remote archive credentials, provision the same instance ID, import the
off-host archive, then prepare and confirm restoration. Preserve the supervisor
configuration, host credentials, archive IDs, and offline decryption identity
outside that host. Instance archive definitions must match the chosen profile
and startup setting. The supervisor process itself is managed by the operating
system service manager.
