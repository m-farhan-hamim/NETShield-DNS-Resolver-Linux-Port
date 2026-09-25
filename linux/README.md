# NetShield DNS Resolver for Linux (Debian package)

Headless Linux port of the NetShield Android app: a local DNS resolver and
sinkhole (ad/tracker blocker) that runs as a systemd service. Same resolution
pipeline as the app - trusted bypass, per-client policy, local records,
blocklist sinkhole, response cache, DoH/DoT/UDP upstream with UDP fallback.

Plain Java 17+, **no third-party libraries**. Packaged as an architecture-independent
`.deb` (`netshield-dns_<version>_all.deb`, also published as `main.deb`).

## Install

```
sudo apt install ./main.deb
netshield status
```

The service starts on `127.0.0.1:5335` (UDP+TCP), downloads the default
blocklists shortly after first start, and answers from then on.

```
dig @127.0.0.1 -p 5335 doubleclick.net      # blocked  -> 0.0.0.0
dig @127.0.0.1 -p 5335 example.com          # forwarded upstream (DoH)
```

Supported: Debian 12+ and Ubuntu 22.04+ (needs a Java 17+ runtime, pulled in as a dependency).

## The `netshield` command

| Command | What it does |
| --- | --- |
| `netshield status` | state, upstream, rule counts, query stats |
| `netshield pause [10m]` / `resume` | stop / restore blocking (default 5 minutes) |
| `netshield sync` | download the lists in `sources.list` now |
| `netshield reload` | re-read config, rules and cached lists |
| `netshield check <domain>` | explain how a domain would be handled |
| `netshield logs [N]` | last N queries |
| `netshield flush` | clear the response cache |

The control socket is `/run/netshield/control.sock` (root + group `netshield`).
Use `sudo`, or `sudo usermod -aG netshield $USER`.

## Configuration (`/etc/netshield/`)

| File | Purpose |
| --- | --- |
| `netshield.conf` | listen address/port, upstream, block action, cache, limits, logging |
| `rules.conf` | `block`, `allow`, `map` rules |
| `sources.list` | blocklist URLs (AdAway and StevenBlack by default) |
| `trusted.list` | domains that bypass blocking and limits |

Edit, then `sudo netshield reload`. Changing `listen_address` or `port` needs
`sudo systemctl restart netshield-dns`.

Logs: `journalctl -u netshield-dns`. Query log: `/var/log/netshield/queries.log`
(set `log_queries=false` to keep none).

### Using it as this machine's DNS

Point resolv.conf (or systemd-resolved's `DNS=`) at `127.0.0.1` on port 53. To
serve on 53, set `port=53` and free the port first
(`DNSStubListener=no` in `/etc/systemd/resolved.conf`). If you do this, use an
IP-literal `doh_url` (e.g. `https://1.1.1.1/dns-query`), otherwise resolving the
upstream's own hostname loops back into NetShield.

## What was ported, and what was not

| Android app | Linux port |
| --- | --- |
| Local server mode (`DnsServerService`) | `DnsServer` (UDP + TCP) |
| `DnsResolverEngine` | `Engine` |
| `BlocklistManager`, `TrustedListManager` | `RuleSet` (`rules.conf`, `sources.list`, `trusted.list`) |
| `DnsPacketParser`, `DnsCache`, `DoHClient`, `DoTClient`, `DnsUdpClient` | same names, same package `com.psbdx.netshield` |
| Hotspot per-device block / daily limits | `blocked_clients`, `daily_query_limit`, `client_daily_limit` |
| Pause tile / notification actions | `netshield pause` / `resume` |
| SQLite log tables | rotated TSV file + in-memory tail |
| `SharedPreferences` (`dns_prefs`) | `netshield.conf` (same key names) |

Not ported because they only make sense on Android: VPN mode (`DnsVpnService`),
split tunnelling and per-app trust (`AppUidResolver`), VPN profile import
(WireGuard/OpenVPN), the UI, widgets, Quick Settings tile, boot receiver, APK
update checker, DNS benchmark UI.

### Deliberate differences

- Listens on `127.0.0.1:5335` by default (the Android app listens on all
  interfaces, port 5353). A Linux box is often internet-facing and an open
  resolver is an abuse risk; opt in with `listen_address`.
- Downloaded blocklists are kept apart from your rules and cached on disk. (In
  the Android code `reloadRules()` clears the same set the downloaded lists are
  added to, so editing a rule drops every downloaded list until the next sync.)
- Sinkhole replies only fabricate an address for `A`/`AAAA`; other types
  (`HTTPS`, `TXT`, ...) get an empty `NOERROR`. Local records only answer the
  matching address family.
- DoT verifies the server certificate's hostname.
- Upstream failures return `SERVFAIL` immediately instead of silence.
- UDP answers larger than the client's buffer are truncated (TC bit) so the
  client retries over TCP.
- No sample rules ship active (the Android seed rules mapped `nas.home` and
  `router.local` to made-up addresses).

## Building

```
linux/packaging/build-deb.sh          # needs JDK 17+, dpkg-deb; writes linux/dist/
```

Runs the unit tests (`linux/src/test`), builds the jar, stages the package tree
and runs `dpkg-deb`. Version comes from `versionName` in
`app/build.gradle.kts` unless `DEB_VERSION` is set. CI: `.github/workflows/build-deb.yml`.

Integration smoke test (starts the real daemon against a fake upstream):

```
linux/tests/smoke.sh
```

## License

GPL-3.0-or-later, same as the app.
