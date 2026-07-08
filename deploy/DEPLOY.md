# Deploy Emergency Tunnel & publish a one-command install link

This is the practical runbook: get the project onto a server and give users a
single command to install it.

> **Important:** the GitHub repo `AMirHossein-donyavii/tunnel` is currently
> **private**, so `raw.githubusercontent.com/...` and release-asset URLs return
> 404 for anyone without access. A public GitHub one-liner therefore does **not**
> work until you either make the repo public (**Path B**) or host the files
> yourself (**Path A**). Pick one.

---

## Path A — Host it on your own Linux server (keeps the repo private)

You serve the installer + prebuilt binaries from your own domain over HTTPS.
End users never touch GitHub.

### 0. Prerequisites
- A Linux server with a public IP.
- A domain/subdomain pointing at it, e.g. `dl.example.com` (DNS **A** record).
- Ports **80** and **443** open.

### 1. Build the release tree (on a machine with Go, e.g. your laptop)
```bash
git clone https://github.com/AMirHossein-donyavii/tunnel.git
cd tunnel
scripts/build-release.sh 1.2.0 --channel stable
# → produces ./release/ with releases/v1.2.0/{binaries,SHA256SUMS,...},
#   the `stable` channel pointer, and a copy of install.sh
```
*(Optional but recommended: sign it so installs verify offline.)*
```bash
minisign -G -p minisign.pub -s minisign.key       # one time; keep .key OFFLINE
MINISIGN_KEY=./minisign.key scripts/build-release.sh 1.2.0 --sign
cp minisign.pub release/minisign.pub
```

### 2. Point install.sh at YOUR host (before uploading)
Edit two lines at the top of `release/install.sh`:
```bash
ET_SOURCE="${ET_SOURCE:-host}"                       # was: github
ET_BASE_URL="${ET_BASE_URL:-https://dl.example.com}" # your domain
# If you signed, also paste the 2nd line of minisign.pub:
ET_PUBKEY="${ET_PUBKEY:-RWQ...your-public-key...}"
```

### 3. Copy the tree to the server's web root
```bash
rsync -av --delete ./release/ root@dl.example.com:/var/www/emergency-tunnel/
```
Resulting layout (served at `https://dl.example.com/`):
```
/var/www/emergency-tunnel/
├── install.sh          ← the public installer
├── stable              ← "1.2.0"
├── minisign.pub        ← (if you signed)
└── releases/v1.2.0/    ← binaries + SHA256SUMS(+.minisig)
```

### 4. Serve over HTTPS (pick one; configs are in this repo)
**Caddy (auto-HTTPS, simplest):**
```bash
# edit the domain in deploy/caddy/Caddyfile, then:
caddy run --config deploy/caddy/Caddyfile
```
**nginx + certbot:**
```bash
cp deploy/nginx/emergency-tunnel.conf /etc/nginx/conf.d/
# edit server_name, then:
certbot --nginx -d dl.example.com
nginx -t && systemctl reload nginx
```

### 5. Test, then share the command
```bash
# quick check the files are reachable:
curl -fsSL https://dl.example.com/stable          # -> 1.2.0
curl -fsSIL https://dl.example.com/install.sh | head -1
```
**Your users run:**
```bash
curl -fsSL https://dl.example.com/install.sh | bash
```

### Publishing a new version later
```bash
scripts/build-release.sh 1.3.0 --channel stable    # (repeat step 1–2)
rsync -av ./release/ root@dl.example.com:/var/www/emergency-tunnel/
```
`rsync` adds `releases/v1.3.0/` and rewrites `stable` → `1.3.0`. Existing users
update by re-running the same one-liner (idempotent; restarts active tunnels).

---

## Path B — Make the GitHub repo public (zero server, works instantly)

If you're OK exposing the source + commit history publicly, this is the fastest
option — `install.sh` already defaults to GitHub-release mode with your repo slug.

### 1. Flip visibility to public
Web: **Settings → General → Danger Zone → Change visibility → Public.**
Or CLI:
```bash
gh repo edit AMirHossein-donyavii/tunnel --visibility public --accept-visibility-change-consequences
```

Before you do, confirm no secrets are in the history (this project's `.gitignore`
excludes `*.key`/`*.sec`/`minisign.key`, and no tokens were ever committed).

### 2. That's it — the command works immediately
```bash
curl -fsSL https://raw.githubusercontent.com/AMirHossein-donyavii/tunnel/main/scripts/install.sh | bash
```
It resolves the latest GitHub Release, downloads the correct-arch binary + panel
+ unit, verifies each against `SHA256SUMS` (over GitHub's TLS), installs, wires
systemd, and launches the panel. Pin a version with `| bash -s -- --version 1.2.0`.

---

## What the user gets, and how they deploy

Either path runs the **same** installer. After it finishes, the user runs `et`
and, in the panel:
1. **Create tunnel** → choose engine (**mux** recommended), role (**iran**/**kharej**),
   direction, ports, and generate/paste the shared **PSK** (same on both servers).
2. The panel writes `/etc/emergency-tunnel/<name>.toml` and starts
   `emergency-tunnel@<name>.service`.

So the full end-user flow is exactly: **run the one-liner → run `et` → create the
tunnel on each of their two servers with the same PSK.**

---

## Test before going public (both paths)

```bash
# 1) static checks
bash -n scripts/install.sh && shellcheck scripts/install.sh

# 2) dry run against a local server (no TLS, no real domain)
scripts/build-release.sh 1.2.0
cd release && python3 -m http.server 8080 &
# in a throwaway root container/VM:
ET_SOURCE=host ET_ALLOW_INSECURE=1 ET_BASE_URL=http://127.0.0.1:8080 \
  bash /path/to/scripts/install.sh

# 3) tamper test — flip a byte in a binary under releases/vX/, re-serve,
#    and confirm the installer aborts with a checksum error instead of installing.
```
Test on Ubuntu/Debian (apt), Rocky/Alma (dnf), and Alpine (apk) to exercise the
package-manager branches.

See [HOSTING.md](HOSTING.md) for the deeper reference (file layout, signing,
channels, caching, maintenance).
