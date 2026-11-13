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
  "instances": {
    "gateway": {
      "start_command": "federated-server run --config /srv/jlucraft/host.json",
      "stop_command": "",
      "kind": "service",
      "auto_start": true
    }
  }
}
```

Kinds are `java`, `bedrock`, and `service`. Place prepared instance files in
`data/instances/<id>`. Commands come from the operator's configuration. The
executor accepts start, stop, and restart jobs from the central service; it does
not expose a shell or accept game session credentials. Empty stop commands use
SIGTERM on Unix, and `^C` uses SIGINT. Processes stop before lifecycle completion.

Store the 32-byte hexadecimal credential outside the repository in a regular
file with mode 0600. Configure its matching value in the skin station's private
environment. Keep the loopback executor behind an HTTPS reverse proxy when the
skin station runs remotely. The skin station checks account identity, OAuth
scope, and the instance's central permission binding. A site administrator assigns
each instance to the appropriate club or global scope.

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
