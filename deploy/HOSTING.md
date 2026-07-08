# Emergency Tunnel — Hosting & Release Guide

This explains how to host the installer on **your** Linux server, publish a public
`curl | bash` URL, verify integrity, test safely, and manage versions/updates.

The model: you build prebuilt binaries **once** on a build machine, sign them, and
serve static files over HTTPS. Users' servers only **download + verify + install** —
they never need Go. (A `--from-source` fallback exists for air-gapped/edge cases.)

---

## 1. Recommended server-side file structure

Everything lives under one web root, e.g. `/var/www/emergency-tunnel`, served at
`https://dl.example.com/`:

```
/var/www/emergency-tunnel/
├── install.sh                     # the public installer (what users curl)
├── install.sh.sha256              # convenience checksum of the installer
├── minisign.pub                   # your release signing PUBLIC key
├── stable                         # text file: current stable version, e.g. "1.0.0"
├── beta                           # (optional) current beta version
└── releases/
    ├── v1.0.0/
    │   ├── et-core-linux-amd64
    │   ├── et-core-linux-arm64
    │   ├── et-core-linux-armv7
    │   ├── et-panel.sh
    │   ├── uninstall.sh
    │   ├── emergency-tunnel@.service
    │   ├── SHA256SUMS             # checksums of all files in this dir
    │   ├── SHA256SUMS.minisig     # detached minisign signature of SHA256SUMS
    │   └── manifest.json
    └── v1.0.1/ ...
```

Design points:
- **`stable`/`beta` are indirection.** The installer reads them to learn the current
  version, so publishing a release = writing one line. Rollback = write the old line.
- **`releases/vX.Y.Z/` is immutable.** Once published, never edit — only add new
  versions. This makes aggressive caching safe and upgrades/downgrades deterministic.
- **The signing secret key NEVER goes on the web server.** Only `minisign.pub` and
  `.minisig` signatures are public.

---

## 2. Build a release (on your build machine)

Needs the Go toolchain. From the repo:

```bash
# one-time: create a signing keypair (keep the .key OFFLINE / in a secret store)
minisign -G -p minisign.pub -s minisign.key

# build v1.0.0 for all arches, checksum + sign, stage the web tree
MINISIGN_KEY=./minisign.key scripts/build-release.sh 1.0.0 --channel stable --sign

# result is staged in ./release/  — copy your pubkey in too
cp minisign.pub release/minisign.pub
```

`build-release.sh` cross-compiles static (`CGO_ENABLED=0`) binaries for
amd64/arm64/armv7, stamps the version via ldflags, writes `SHA256SUMS`, signs it,
writes `manifest.json`, sets the channel pointer, and copies `install.sh`.

---

## 3. Host it (publish the staged tree)

Copy `./release/` to your web root and serve over HTTPS.

```bash
rsync -av --delete ./release/ root@dl.example.com:/var/www/emergency-tunnel/
```

### Web server — pick one

**nginx** (config provided in `deploy/nginx/emergency-tunnel.conf`):
```bash
apt install -y nginx certbot python3-certbot-nginx
cp deploy/nginx/emergency-tunnel.conf /etc/nginx/conf.d/
# edit server_name to your domain, then:
certbot --nginx -d dl.example.com
nginx -t && systemctl reload nginx
```

**Caddy** (auto-HTTPS, simplest — `deploy/caddy/Caddyfile`):
```bash
# install Caddy, then:
caddy run --config deploy/caddy/Caddyfile     # or run it as a systemd service
```

Both are configured to serve `.sh`/channel/checksum files as `text/plain`, disable
directory listing, cache `releases/*` immutably, and block dotfiles/secret keys.

---

## 4. Create & manage the installation URL

The public URL is simply `https://dl.example.com/install.sh`. Point the installer at
your host by editing **one line** at the top of `scripts/install.sh` before you build:

```bash
ET_BASE_URL="${ET_BASE_URL:-https://dl.example.com}"
```

and paste your public key so users get offline signature verification:

```bash
ET_PUBKEY="${ET_PUBKEY:-RWQ....your-minisign-public-key-second-line....}"
```

(Users can still override with `ET_BASE_URL=... | bash` for mirrors/testing.)

A short, memorable URL is nice: put the site at the apex or a `get.` subdomain, or
add an alias `https://example.com/install.sh` that proxies to the release host.

---

## 5. How users install on a fresh Linux server

One command:
```bash
curl -fsSL https://dl.example.com/install.sh | bash
```

Variants (args pass through the pipe with `-s --`):
```bash
# pin an exact version
curl -fsSL https://dl.example.com/install.sh | bash -s -- --version 1.0.0
# beta channel
curl -fsSL https://dl.example.com/install.sh | bash -s -- --channel beta
# reinstall / repair
curl -fsSL https://dl.example.com/install.sh | bash -s -- --force
# uninstall
curl -fsSL https://dl.example.com/install.sh | bash -s -- --uninstall
```

What the installer does, in order: detect Linux distro + arch → ensure `curl`/
`sha256`/`tar` → resolve version from the channel → download `SHA256SUMS` → verify
its **minisign signature** (if `ET_PUBKEY` is set) → download the correct-arch binary,
panel, unit, uninstaller → verify **each** against `SHA256SUMS` → install with strict
permissions → `daemon-reload` → run `et-core version` to confirm → offer to launch `et`.

After install users just run `et`.

---

## 6. Test the installer BEFORE going public

**a) Static checks**
```bash
bash -n scripts/install.sh              # syntax
shellcheck scripts/install.sh           # lint (install shellcheck)
```

**b) Serve locally and dry-run against localhost** (no real domain, no TLS):
```bash
scripts/build-release.sh 1.0.0 --channel stable         # stage ./release
cd release && python3 -m http.server 8080 &             # quick static server
# In a throwaway root shell / container:
ET_ALLOW_INSECURE=1 ET_BASE_URL=http://127.0.0.1:8080 \
  bash scripts/install.sh
```
`ET_ALLOW_INSECURE=1` permits the plain-HTTP localhost origin for testing only.

**c) Full end-to-end in a disposable VM/container** (closest to a real user):
```bash
docker run --rm -it -p 8080 ubuntu:22.04 bash
# inside: apt update && apt install -y curl ca-certificates
# point at your host (or a container serving ./release) and run the one-liner
```
Test on at least Ubuntu/Debian (apt), Rocky/Alma (dnf), and Alpine (apk) to exercise
the package-manager branches. Verify: binary runs, `systemctl` sees the template unit,
a test tunnel starts, then `--uninstall` cleans up.

**d) Tamper test** (prove verification works): flip a byte in a binary under
`releases/vX/`, re-serve, and confirm the installer aborts with a checksum/signature
error instead of installing.

---

## 7. Maintaining & updating future versions

**Cut a new version**
```bash
echo "1.0.1" > VERSION
git tag v1.0.1
MINISIGN_KEY=./minisign.key scripts/build-release.sh 1.0.1 --channel stable --sign
rsync -av ./release/ root@dl.example.com:/var/www/emergency-tunnel/
```
The `rsync` adds `releases/v1.0.1/` and rewrites the `stable` pointer to `1.0.1`.
Existing `releases/v1.0.0/` stays intact, so pinned users are unaffected.

**Promote through channels**
- Publish to `beta` first: `... --channel beta`. Testers run `--channel beta`.
- When happy, run the same build `--channel stable` (or just copy the version into
  `stable`). Channels are independent lines; a version can be in both.

**How users update**
- `et` → menu **8) Update core** (re-runs the installer from the recorded host,
  verifies, and restarts running tunnels), or
- the same `curl … | install.sh | bash` again — it's **idempotent**: it detects the
  installed version, upgrades, and restarts active `emergency-tunnel@*` services.

**Rollback**
```bash
echo "1.0.0" > /var/www/emergency-tunnel/stable      # point the channel back
```
Users who update next will move to 1.0.0; nothing else changes.

**Housekeeping / good practices**
- Keep a `CHANGELOG.md`; tag every release in git (`vX.Y.Z`) so builds are reproducible.
- Retain the last few `releases/vX/` dirs; prune very old ones only if disk-bound.
- Rotate the signing key rarely and deliberately; if you must, ship a new `install.sh`
  carrying the new `ET_PUBKEY` and keep signing with the old key for one release cycle.
- Monitor access logs for `install.sh` pulls and 404s (a 404 on a channel/asset means
  a broken publish). Consider a CI job that runs sections 6a–6c on every tag.
- Never expose the signing secret, `.env`, or `minisign.key` under the web root — the
  provided nginx/Caddy configs already deny `.*`, `*.key`, `*.sec`.
```
