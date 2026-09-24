# Fail2ban for NethServer 8

An NS8 module with one shared list of permanently blocked IPs and one shared
whitelist. One module provides the coordinator; other NS8 modules connect to it.
The coordinator participates automatically. There are no groups or per-node ban
scopes. This project targets NS8, including separate NS8 installations.

## Behavior

- Fail2ban 1.1.1 detects repeated authentication failures: five failures in ten
  minutes in a jail. Discovery covers host SSH, NS8 cluster-admin, Gitea, Organizr
  and Samba, and runs once per minute.
- A ban blocks **all IP traffic, all ports and all protocols**, IPv4 and IPv6:
  input from the IP, output to it, and forwarding in either direction. An
  independent nftables table runs before ordinary filter rules, including rules
  accepting established connections. No `all-services` port list is involved.
- Every ban is permanent (`bantime = -1`, nft sets without timeouts). Only a manual
  shared unban or an explicit matching whitelist change removes it. Stopping or
  reloading a jail does not remove a shared ban. Removing the module removes its
  firewall table from that host.
- The coordinator includes an **SQLite database**. It is owned exclusively by
  the sync service, so PostgreSQL and a separately managed database service are
  unnecessary. Peers use an authenticated HTTPS API, never a shared SQLite file.
- An offline node keeps its existing bans and whitelist indefinitely, enforces
  new local bans immediately, and queues them for synchronization. Connected
  nodes poll every three seconds. An unreachable node learns changes when it
  reconnects; global manual operations require the coordinator to be reachable.
- Manual unban tombstones and whitelist history prevent delayed messages from
  resurrecting obsolete bans. New failures **after** the node learns of a manual
  unban can trigger a new ban. Retried sync events are idempotent.
- ntfy sends only for a new ban triggered by sufficient **local** login failures.
  Imported bans and Fail2ban database restoration do not notify. Messages contain
  UTC date/time, IP, jail, node/module and original matching log lines. A durable
  queue retries failed deliveries. Messages over ntfy's normal message size use
  a text attachment. After a lost HTTP acknowledgment, a retry can result in a
  duplicate notification; ntfy does not provide an idempotent publish API.

## Settings

1. Install one instance per protected NS8 node.
2. On the first module, choose **Provide the coordinator** and enter a public
   HTTPS URL such as `https://bans.example.org`. Point its DNS to this node.
   NS8 Traefik provides the reverse proxy and requests the certificate. The
   internal service listens only on loopback at an NS8-allocated port. The
   database has no network listener, port setting or external credentials.
3. Save, then reveal the connection token. On other modules, choose **Connect
   to the coordinator**, enter its URL and token, and save. Public HTTPS must
   have a certificate trusted by those nodes. The coordinator itself uses its
   private loopback endpoint automatically.
4. Enter whitelist addresses or ranges, one per line. IPv4, IPv6, CIDR and
   `first-last` ranges are supported. Whitelist edits apply to the shared list
   and clear matching bans. Concurrent edits require a refresh before overwriting
   another administrator's changes. The local-only loopback networks remain
   whitelisted so an authentication failure cannot break internal NS8 services.
5. Select blocked addresses and click **Unblock selected**. This changes the
   common list; no node/scope choice is required.
6. Optionally enable notifications and set the ntfy server URL, topic and token.
   Blank token fields retain stored secrets. The saved ntfy token can be removed
   explicitly. No event, rate-limit or notification-threshold settings exist.

The coordinator/peer role is chosen at first setup. Creating another module to
change roles avoids accidentally merging independent authority databases. A
coordinator clone automatically becomes a peer of the original coordinator.

## Jail discovery and application logs

Jails determine **where failed logins are detected**, not which traffic is
blocked. Every supported jail calls the same ban action and firewall.

| Jail | Source | Detection |
| --- | --- | --- |
| SSH | Host systemd journal | Failed password, public-key and keyboard-interactive/PAM authentication |
| NS8 admin | Local Traefik access log | HTTP 401 on POST `/cluster-admin/api/login`, specifically the NS8 admin router/backend |
| Gitea | Application container journal | Failed web/API authentication records and SSH authentication failures |
| Organizr | JSON authentication logs in its NS8 application volume | `Wrong Password` and `Incorrect 2FA`; extra lockout messages are not counted twice |
| Samba | Container JSON authentication audit log | Failed authentications with an actual remote IP |

Samba's NS8 default disables authentication audit events. Discovery persists an
`auth_json_audit` level of at least 2 and applies it live with `smbcontrol`, without
restarting Samba. Other logging settings are retained. The logging setting stays
enabled after this module is removed. Organizr creates its log file upon login
activity; until a file exists, the settings page reports that it is waiting.

Application-specific parsing is needed because failed logins are represented
differently. For example, Gitea may return HTTP 200 for a wrong password, while
NS8's password error message lacks the client IP, so the admin access log is
used. Searching every log for an arbitrary IP would produce incorrect bans.
This is an input-format issue, not a restriction on the resulting ban.

A host firewall can match only addresses present in IP packets. With a separate
upstream proxy, CDN, source NAT or an application doing an LDAP bind on behalf of
another client, the immediate network peer may differ from the original client.
Trusted proxies/application servers and management/inter-node addresses belong
in the shared whitelist when needed. A ban on an original client hidden behind
an upstream proxy needs enforcement at that proxy as well. The module cannot
reconstruct an IP that the application never records. Rootless network address
translation can likewise obscure the source seen by an application's own SSH
server. Diagnostics lists discovered sources and operational failures.

## Architecture and recovery

The rootful module owns host services for collection, synchronization, nftables
reconciliation, notification delivery and the coordinator. The pinned Fail2ban
engine runs in a container with no network and no capabilities. Its Python action
writes to the durable node queue; no log content or IP is interpolated into shell
commands. The worker owns firewall enforcement and retries independently of
HTTPS or ntfy availability. The module never flushes the host firewall ruleset.

Host-wide input, output and forwarding hooks require an NS8 rootful module.
Clusters that enforce certification for third-party rootful applications must
trust/certify this package before installation; a rootless implementation could
not provide the requested all-traffic host firewall behavior.

State and secrets are stored under the module's private NS8 state directory.
NS8 backups include online SQLite backup snapshots and configuration. Live WAL
files are not copied as an inconsistent database backup. Restore reconstructs
the services and the NS8 route. Coordinator identity/revision checks detect a
replaced database or a rollback relative to a peer: recover the latest coordinator
backup instead of silently dropping newer bans.

Recovery from an external firewall table deletion happens within 15 seconds.
The periodic reconciliation does not make bans expire. A separate boot service
restores cached bans before `network-pre.target`. Transparent
layer-2 bridge switching or traffic offloaded completely outside host netfilter
is outside the host `inet` hooks; normal NS8 host/routed container traffic uses
these hooks. Kernel-level namespace tests exercise both IP families and all
three hooks.

## Build and validation

```bash
PYTHONPATH=imageroot/pypkg python3 -m unittest discover -s tests -v
# Include the actual daemon integration test:
PYTHONPATH=imageroot/pypkg FAIL2BAN_SOURCE=/path/to/fail2ban-1.1.1 \
  REQUIRE_ENGINE_TEST=1 python3 -m unittest discover -s tests -v
cd ui
corepack yarn install --immutable
corepack yarn exec eslint --ext .js,.vue src
NODE_OPTIONS=--openssl-legacy-provider corepack yarn build
```

`build-images.sh` uses Buildah, Git and Node 24/Corepack to build the engine and
module. Upstream Fail2ban is pinned to commit
`f60978618a101427b06924fc932b44350fec2b63` (1.1.1). Engine tags include the module
commit, so updates select matching Python actions and node code. After all
validation jobs, including the NS8 VM test, succeed on `main`, the workflow
publishes `ghcr.io/platypuschan/fail2ban-reworked:dev` and a matching engine.
The separate **Build installable NS8 images** workflow also supports manual
builds and versioned `v*` tags. Both the `fail2ban-reworked` and `fail2ban-engine`
packages must be public for unauthenticated NS8 installation.

```bash
# After the image build succeeds, on an NS8 cluster leader:
add-module ghcr.io/platypuschan/fail2ban-reworked:dev <node-id>
```

The validation workflow tests synchronization, outage/replay handling, concurrent
updates, parsers, authenticated HTTP, a real Fail2ban process, actual nftables
traffic enforcement in isolated network namespaces, and the production UI build.
It also installs a fresh NS8 cluster in a disposable Rocky Linux 9 VM and checks
module installation, five actual failed admin logins, blocking, ntfy delivery,
the Traefik route, imported bans without notifications, manual unban, whitelist,
SQLite backup snapshots, service restart and removal. The VM's reserved test
hostname uses a self-signed certificate. Real ACME certificate issuance,
complete NS8 backup/restore and live Gitea/Organizr/Samba authentication remain
deployment checks; those application parsers are covered by log fixtures.

## References

- [NS8 Organizr module](https://github.com/Platypuschan/ns8-organizr-reworked): native Vue/Carbon UI, tasks, routing and packaging.
- [NS8 Gitea module](https://github.com/Platypuschan/ns8-gitea-reworked): application environment, container and SSH exposure.
- [NS8 Samba module](https://github.com/Platypuschan/ns8-samba-reworked) and [upstream](https://github.com/NethServer/ns8-samba): container lifecycle, JSON auditing and notification settings.
- [NS8 core](https://github.com/NethServer/ns8-core) and [Traefik](https://github.com/NethServer/ns8-traefik): rootful lifecycle, backup hooks, task secret masking and admin route/access logging.
- [Fail2ban 1.1.1](https://github.com/fail2ban/fail2ban/tree/1.1.1): Python actions, restored-ticket behavior and persistent jails.
- [Gitea Fail2ban documentation](https://docs.gitea.com/administration/fail2ban-setup/), [Organizr source](https://github.com/causefx/Organizr) and [Samba logging levels](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html).

GPL-3.0-or-later. The UI scaffold retains the upstream Nethesis copyright notices.
