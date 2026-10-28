# fail2ban rule set for web hosts

Drop-in jails and filters for a typical Linux web server: SSH, Apache or
nginx, WordPress, Laravel, and the scanner traffic every public host sees
(`.env`, `.git/`, backup archives, webshell probes). Everything here is a
plain fail2ban config file. Nothing touches `jail.conf` or `jail.local`, so it
is safe to install next to an existing setup and remove again later.

Tested against fail2ban 1.0.2. Works on 0.10+.

## What is in the box

| File | Jail(s) | Watches | Catches |
|---|---|---|---|
| `jail.d/00-f2b-defaults.local` | `[DEFAULT]` | - | Shared settings: whitelist, ban times, backend, nftables action |
| `jail.d/sshd.local` | `sshd` | journal | SSH brute force, invalid users, scanner handshakes |
| `jail.d/apache2.local` | `apache-auth` `apache-badbots` `apache-noscript` `apache-overflows` `apache-botsearch` | `/var/log/apache2/*` | Basic-auth failures, bad bots, script probes, overflow URLs |
| `jail.d/nginx.local` | `nginx-http-auth` `nginx-botsearch` `nginx-limit-req` `nginx-bad-request` | `/var/log/nginx/*` | Basic-auth failures, probes, rate-limit trips, malformed requests |
| `jail.d/wordpress.local` | `wordpress-login` `wordpress-xmlrpc` | web access log | Failed `wp-login.php` POSTs, `xmlrpc.php` abuse |
| `jail.d/laravel.local` | `laravel-auth` `laravel-login-http` | `storage/logs/laravel*.log`, web access log | Failed logins logged by the app, or rejected at HTTP level |
| `jail.d/git-probe.local` | `git-probe` | web access log | Any request for `/.git/`, `/.svn/`, `/.hg/`, `/.bzr/` |
| `jail.d/env-probe.local` | `env-probe` | web access log | `.env*`, cloud credentials, `phpinfo`, config backups, webshells, dumps |
| `jail.d/recidive.local` | `recidive` | fail2ban's own log | IPs banned 3 times in a day get two weeks |
| `filter.d/f2b-*.conf` | - | - | The custom filters the jails above reference |
| `cloudflare/`, `action.d/f2b-cloudflare.conf`, `jail.d/cloudflare.local.example` | - | - | Only for servers behind Cloudflare: realip, edge bans (see *Behind a proxy or CDN*) |
| `samples/` | - | - | Log lines for testing the filters with `fail2ban-regex` |

The stock filters that ship with fail2ban (`sshd`, `apache-*`, `nginx-*`,
`recidive`) are used wherever they exist. Custom filters are prefixed `f2b-`
so they never shadow a stock file.

## Install

1. Install fail2ban and make sure it runs.

   ```bash
   sudo apt install fail2ban          # Debian / Ubuntu
   sudo dnf install fail2ban          # RHEL / Fedora
   sudo systemctl enable --now fail2ban
   ```

2. Copy the filters, then only the jail files for services you actually run.
   A jail whose log files do not exist is skipped with a warning, so copying
   everything is harmless, but it keeps `f2b jails` tidy to leave out what you
   do not use.

   ```bash
   cd rules
   sudo cp filter.d/*.conf /etc/fail2ban/filter.d/
   sudo cp jail.d/00-f2b-defaults.local jail.d/recidive.local /etc/fail2ban/jail.d/
   sudo cp jail.d/sshd.local /etc/fail2ban/jail.d/
   sudo cp jail.d/nginx.local /etc/fail2ban/jail.d/        # or apache2.local
   sudo cp jail.d/git-probe.local jail.d/env-probe.local /etc/fail2ban/jail.d/
   sudo cp jail.d/wordpress.local /etc/fail2ban/jail.d/    # if you host WordPress
   sudo cp jail.d/laravel.local /etc/fail2ban/jail.d/      # if you host Laravel
   ```

3. **Edit `ignoreip`** in `/etc/fail2ban/jail.d/00-f2b-defaults.local`. Add
   your office, VPN and monitoring addresses. A typo here locks you out of
   your own server, so do this before reloading.

4. Check the configuration parses and see which jails will start.

   ```bash
   sudo fail2ban-client -d >/dev/null && echo OK
   ```

   Warnings like `Have not found any log file for nginx-http-auth jail` mean
   that jail will be skipped because the log path does not exist on this host.
   That is expected for services you do not run.

5. Reload and verify.

   ```bash
   sudo fail2ban-client reload
   sudo f2b jails            # or: sudo fail2ban-client status
   ```

## Per-service notes

### Defaults (`00-f2b-defaults.local`)

| Setting | Value | Meaning |
|---|---|---|
| `bantime` | 1h | First ban |
| `bantime.increment` | on, factor 2, max 1w | Each repeat ban doubles, capped at a week |
| `findtime` / `maxretry` | 10m / 5 | Five failures in ten minutes |
| `banaction` | `nftables[type=allports]` | Block every port, not just the one attacked |

If the host uses iptables rather than nftables, change the last line to
`banaction_allports = iptables-allports`. To receive an e-mail per ban,
uncomment the `destemail`, `sender` and `action` lines and make sure
`sendmail` or an equivalent MTA works.

### SSH (`sshd.local`)

Reads the systemd journal, so nothing to configure. `mode = aggressive` also
bans clients that disconnect before authenticating or probe supported
algorithms, which is most scanner traffic. If you run an SSH client
integration that reconnects noisily, switch to `mode = normal`.

If SSH listens on a non-standard port, fail2ban still bans all ports, so the
`port = ssh` line only affects the log message.

### Apache (`apache2.local`)

All stock filters. Log globs match per-vhost files such as
`example.com-access.log` and `example.com-error.log`.

- `apache-noscript` bans clients asking for `.php`, `.asp`, `.cgi` files that
  do not exist. On a PHP site where 404s for `.php` are routine, disable it.
- `apache-fakegooglebot` is shipped disabled because it does a DNS lookup per
  matching line.

### nginx (`nginx.local`)

All stock filters. `nginx-limit-req` only does something if nginx has a
`limit_req` zone configured. A sensible one for a login page:

```nginx
# in http {}
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

# in the server {} block
location = /login {
    limit_req zone=login burst=5 nodelay;
    try_files $uri /index.php?$query_string;
}
```

nginx then writes `limiting requests, excess: ...` to `error.log` and the
jail bans after 10 such lines in a minute.

### WordPress (`wordpress.local`)

Works from the web server access log in the default *combined* format, so no
plugin is needed and it works across every WordPress vhost on the host.

- `wordpress-login`: a failed login POSTs to `wp-login.php` and gets the form
  back with HTTP 200. A successful login answers 302. Five 200s in ten minutes
  is a ban.
- `wordpress-xmlrpc`: three POSTs to `xmlrpc.php`. Jetpack, the WordPress
  mobile app and some backup plugins use XML-RPC legitimately. If you rely on
  them, either disable this jail or add the relevant source ranges to
  `ignoreip`. If you do not, consider blocking `xmlrpc.php` at the web server
  as well.

Custom access log formats still work as long as a line begins with the client
IP and the request is quoted in the usual `"POST /path HTTP/1.1" 200` form. If
nginx or Apache sits behind a proxy or CDN, see *Behind a proxy* below.

### Laravel (`laravel.local`)

Laravel does not log failed logins by default, so the main jail needs a small
listener in your application. Register it in `app/Providers/EventServiceProvider.php`
(Laravel 10 and earlier) or `app/Providers/AppServiceProvider.php::boot()`
(Laravel 11+):

```php
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;

Event::listen(Failed::class, function (Failed $event) {
    Log::warning(sprintf(
        'Failed login for %s from %s',
        $event->credentials['email'] ?? 'unknown',
        request()->ip()
    ));
});
```

That writes lines like

```
[2026-09-13 10:15:22] production.WARNING: Failed login for bob@example.com from 203.0.113.9
```

to `storage/logs/laravel.log`, which `laravel-auth` watches. Then:

- Set `logpath` in `laravel.local` to your deploy path. The default glob
  `/var/www/*/storage/logs/laravel*.log` covers one level of sites and daily
  log files.
- `request()->ip()` must return the real client address. If the app runs
  behind a proxy or load balancer, configure trusted proxies
  (`TrustProxies` middleware, or `$middleware->trustProxies()` in Laravel 11)
  or every ban will hit the proxy.
- If you use a dedicated log channel for auth events, point `logpath` at
  that file instead.

`laravel-login-http` is a fallback that needs no code change: it bans on
POSTs to `/login`, `/api/login`, `/api/auth/login` or `/sanctum/token` that
were answered 401, 422 or 429. Classic Blade forms redirect with 302 on both
success and failure, which this filter deliberately ignores, so it mainly
helps JSON, Inertia and API logins. It ships disabled.

### Git probes (`git-probe.local`)

One request for anything under `/.git/`, `/.svn/`, `/.hg/` or `/.bzr/` is a
one-day ban. No legitimate visitor asks for these. Also deny them at the web
server so a misconfigured deploy never serves your history:

```nginx
location ~ /\.(git|svn|hg|bzr) { deny all; return 404; }
```

```apache
<DirectoryMatch "/\.(git|svn|hg|bzr)">
    Require all denied
</DirectoryMatch>
```

### Secret and debug file probes (`env-probe.local`)

Two requests in a day for any of the following is a one-day ban:

- `.env` and variants (`.env.bak`, `.env.production`, `.env-old`, ...)
- `.aws/credentials`, `.ssh/*`, `.htpasswd`, `.DS_Store`, `.idea/`, `.vscode/`
- Backups of config files: `wp-config.php.bak`, `config.php.old`, `settings.php~`, ...
- `phpinfo.php`, `info.php`, `test.php`, Symfony `_profiler/phpinfo`
- `composer.json`, `composer.lock`, `package.json`, `yarn.lock`, `Dockerfile`, `docker-compose.yml`
- Common webshell names: `shell.php`, `c99.php`, `r57.php`, `wso.php`, `alfa.php`, `adminer.php`, ...
- Archives and dumps at the root: `backup.zip`, `site.tar.gz`, `db.sql`, `dump.sql.gz`, ...

If your site legitimately serves one of these names (for example a public
`package.json`, or a real page at `/test.php`), remove that alternative from
the matching `failregex` line in `filter.d/f2b-env-probe.conf`, or add the
path to `ignoreregex`:

```ini
ignoreregex = ^<HOST> -[^"]*"GET /package\.json
```

As with git, deny `.env` at the web server too:

```nginx
location ~ /\.env { deny all; return 404; }
```

### Repeat offenders (`recidive.local`)

Reads `/var/log/fail2ban.log`. Any address banned three times in a day by any
other jail is banned on all ports for two weeks. If fail2ban logs to the
journal on your host (`fail2ban-client get logtarget` says `SYSTEMD` or
`SYSLOG`), uncomment the `backend` and `journalmatch` lines in the file.

## Behind a proxy or CDN

Decide per server, because the two cases need opposite configuration.

| | Reached directly | Behind Cloudflare |
|---|---|---|
| IP in the access log | Real client | Cloudflare's, unless realip is configured |
| Trust `CF-Connecting-IP`? | **No**, anyone can forge it | Yes, but only from Cloudflare's ranges |
| Does an nftables ban stop web traffic? | Yes | **No**, packets come from Cloudflare |
| Ban action for web jails | local (default) | local + `f2b-cloudflare` |
| SSH jail | local | local (SSH is not proxied) |
| Install from `rules/cloudflare/` | nothing | all of it |

Not sure which kind a server is? Compare `curl -sI https://example.com | grep -i
^server` (Cloudflare answers `server: cloudflare`) and check whether the
origin's own IP answers on 443 when you bypass DNS.

### Servers not behind Cloudflare

Nothing extra. Use the install steps above unchanged. Do **not** install the
realip snippet or the Cloudflare action here.

### Servers behind Cloudflare

1. **Restore the real client IP in the log.** Fix the log, not fail2ban.

   ```bash
   sudo cp cloudflare/cloudflare-realip.conf /etc/nginx/conf.d/
   sudo install -m 755 cloudflare/cloudflare-update-ips.sh /usr/local/sbin/
   sudo nginx -t && sudo systemctl reload nginx
   ```

   The script regenerates the snippet from Cloudflare's published ranges;
   run it weekly from cron, since the ranges change. Apache equivalent:
   `mod_remoteip` with `RemoteIPHeader CF-Connecting-IP` and one
   `RemoteIPTrustedProxy` per Cloudflare range, logging `%a` instead of `%h`.

   Verify before enabling any ban: `sudo tail /var/log/nginx/access.log` must
   show visitor addresses, not Cloudflare's (`104.x`, `172.64.x`, `162.158.x`...).

2. **Ban at Cloudflare as well as locally.** A firewall ban on the origin
   cannot block proxied traffic, so add the edge action:

   ```bash
   sudo cp action.d/f2b-cloudflare.conf /etc/fail2ban/action.d/
   sudo cp jail.d/cloudflare.local.example /etc/fail2ban/jail.d/99-f2b-cloudflare.local
   sudo chmod 600 /etc/fail2ban/jail.d/99-f2b-cloudflare.local
   sudoedit /etc/fail2ban/jail.d/99-f2b-cloudflare.local   # token, zone ID, ignoreip
   sudo fail2ban-client reload
   ```

   Needs `curl` and `jq`. Use an API token limited to *Zone > Firewall
   Services > Edit* on that one zone. The drop-in also whitelists Cloudflare's
   ranges, so a broken realip setup can never ban the edge and take the site
   down. It keeps `sshd` and `recidive` on plain local bans.

3. **Close the back door.** If the origin answers on 80/443 for anyone, an
   attacker can skip Cloudflare and the edge bans do nothing. Allow 80/443
   only from Cloudflare's ranges, or use Authenticated Origin Pulls or a
   Cloudflare Tunnel.

Things to know on these servers:

- Cloudflare Access Rules never expire on their own. Unbans are sent when
  fail2ban lifts a ban, but rules can go stale if fail2ban state is lost.
  Plans have a rule limit, so keep `bantime.maxtime` reasonable.
- Requests Cloudflare answers itself (cache hits, WAF blocks, challenges)
  never reach the origin log, so the probe jails only see what got through.
- Laravel: set trusted proxies to Cloudflare's ranges so `request()->ip()` is
  the visitor. WordPress and `nginx-limit-req` depend on the real IP too.

## Testing a filter

`fail2ban-regex` runs a filter against a log file and reports what would
match. Use absolute paths, because the filter's `[INCLUDES]` section is
resolved relative to the filter file's directory.

```bash
# against the bundled samples
fail2ban-regex "$PWD/samples/access.log"  "$PWD/filter.d/f2b-env-probe.conf"
fail2ban-regex "$PWD/samples/laravel.log" "$PWD/filter.d/f2b-laravel-auth.conf"

# against your real log, showing every matching line
fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/f2b-wordpress-login.conf --print-all-matched

# the same through the f2b wrapper
sudo f2b test /var/log/nginx/access.log f2b-wordpress-login
```

Expected results on the samples:

| Filter | Matches |
|---|---|
| `f2b-wordpress-login` | 2 (the two 200 POSTs; the 302 and the plain GET are ignored) |
| `f2b-wordpress-xmlrpc` | 1 |
| `f2b-git-probe` | 2 |
| `f2b-env-probe` | 9 |
| `f2b-laravel-login-http` | 2 (422 and 401; the 302 is ignored) |
| `f2b-laravel-auth` | 3 (including one IPv6 address) |

## Tuning

- **Too aggressive?** Raise `maxretry` or shorten `bantime` in the jail's
  file. Values in `jail.d/*.local` override `00-f2b-defaults.local`.
- **Not catching something?** Run `fail2ban-regex` with
  `--print-all-missed` on a slice of the log to see lines that did not match,
  then extend the relevant `failregex`.
- **Whitelisting**: `sudo f2b whitelist 203.0.113.0/24` adds to a separate
  managed drop-in and reloads. Or edit `ignoreip` in the defaults file.
- **Disable a jail without deleting it**: set `enabled = false` in its file
  and run `sudo fail2ban-client reload`.
- **See what is happening**: `sudo f2b status`, `sudo f2b recent`,
  `sudo f2b top`, or `sudo f2b watch` for a live tail.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Have not found any log file for X jail` | The `logpath` glob matched nothing | Expected if the service is not installed. Otherwise fix the path. |
| Jail starts but never bans | Log format differs from *combined* | Run `fail2ban-regex` on the real log; adjust the regex or the web server log format. |
| Bans hit your proxy or load balancer | Access log records the proxy IP | See *Behind a proxy or CDN*. Make sure Cloudflare-fronted servers have realip set up and direct servers do not. |
| `ERROR ... nftables ... not found` | Host uses iptables | Set `banaction_allports = iptables-allports` in the defaults file. |
| Laravel jail never bans | Listener not registered, or `request()->ip()` returns the proxy | Check `storage/logs/laravel.log` for `Failed login` lines; configure trusted proxies. |
| You locked yourself out | Your own IP was not in `ignoreip` | From another address: `sudo f2b unban <ip>` then `sudo f2b whitelist <ip>`. From console: `fail2ban-client set <jail> unbanip <ip>`. |

## Uninstall

```bash
sudo rm /etc/fail2ban/jail.d/{00-f2b-defaults,sshd,apache2,nginx,wordpress,laravel,git-probe,env-probe,recidive}.local
sudo rm /etc/fail2ban/filter.d/f2b-*.conf
sudo fail2ban-client reload
```

Existing bans issued by the removed jails are dropped on reload.
