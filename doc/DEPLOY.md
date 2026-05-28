# Deploying RonwayScanner to AWS Lightsail

This walks through deploying the `ronway serve` API to an **AWS Lightsail
instance running the Bitnami Nginx blueprint** — the existing Nginx becomes
the HTTPS reverse proxy, and the scanner runs as a Docker container behind it
with a persistent SQLite scan history.

```
  bpxai.com/ronway (frontend)
        │  HTTPS
        ▼
  ┌─────────────────────────────── Lightsail (Singapore) ───────────────┐
  │  Bitnami Nginx  :443  ──reverse proxy──►  ronway (Docker)  :3001     │
  │   (Let's Encrypt / bncert)                 SQLite → /data volume     │
  └─────────────────────────────────────────────────────────────────────┘
```

**Target instance (yours):** `Nginx-1`, 512 MB / 2 vCPU / 20 GB, region
`ap-southeast-1` (Singapore), public IP **<YOUR_INSTANCE_IP>**.

---

## 0. Prerequisites

- A subdomain for the API, e.g. `ronway-api.bpxai.com`.
- Decide it now — you'll create its DNS record in step 5 and TLS in step 7.

---

## 1. Connect to the instance

Easiest: the Lightsail browser SSH (**Connect** tab). To use your own
terminal, connect with the default key you downloaded
(`LightsailDefaultKey-ap-southeast-1.pem`). The Bitnami login user is
`bitnami`.

**Git Bash / macOS / Linux:**

```bash
chmod 600 LightsailDefaultKey-ap-southeast-1.pem   # SSH refuses world-readable keys
ssh -i LightsailDefaultKey-ap-southeast-1.pem bitnami@<YOUR_INSTANCE_IP>
```

If you've moved the key to `~/.ssh/` (recommended):

```bash
ssh -i ~/.ssh/LightsailDefaultKey-ap-southeast-1.pem admin@<YOUR_INSTANCE_IP>
```

**Windows PowerShell** (OpenSSH checks NTFS ACLs, not chmod — tighten them once):

```powershell
icacls .\LightsailDefaultKey-ap-southeast-1.pem /inheritance:r /grant:r "$($env:USERNAME):(R)"
ssh -i .\LightsailDefaultKey-ap-southeast-1.pem bitnami@<YOUR_INSTANCE_IP>
```

> Keep the `.pem` private — store it outside the repo (e.g. `~/.ssh/`). It's
> already covered by `.gitignore` (`*.pem`), so it won't be committed by
> accident, but never paste it anywhere public.

---

## 2. Add swap (required — 512 MB is too little to build)

Compiling the Rust project needs more than 512 MB of RAM. Add a 4 GB swapfile
so the build doesn't get OOM-killed (keep it afterwards — it's a safety net):

```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
free -h   # confirm swap is active
```

> Lighter alternative: build the image elsewhere (or via GitHub Actions),
> push to GHCR/Docker Hub, and `docker pull` here — then no swap is needed.
> The on-box build below is the simplest self-contained path.

---

## 3. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose git

sudo usermod -aG docker bitnami      # run docker without sudo
sudo systemctl enable --now docker
exit                                 # log out/in so the group takes effect
```

Reconnect (`ssh bitnami@<YOUR_INSTANCE_IP>`), then `docker ps` should work.

---

## 4. Build and run the API

```bash
git clone https://github.com/KBPsystem777/ronway-scanner.git
cd ronway-scanner
sudo docker compose up -d --build         # first build is slow on this box (~10–20 min)
```

Confirm it's healthy on loopback (the container binds `127.0.0.1:3001`):

```bash
curl http://127.0.0.1:3001/api/health
# {"status":"ok","service":"ronway-scanner","version":"0.1.0"}
docker compose logs -f               # watch the morgan-style request log
```

Scan history persists in the `ronway_data` Docker volume, so it survives
restarts and redeploys.

---

## 5. Point DNS at the instance

Create an **A record** for your subdomain → the instance IP:

```
ronway-api.bpxai.com.   A   <YOUR_INSTANCE_IP>
```

(Optionally also an AAAA record to the IPv6 shown in the Lightsail console.)
Wait for it to resolve: `dig +short ronway-api.bpxai.com`.

> Recommended: also attach a **static IP** in Lightsail (Networking tab) so
> the address doesn't change if the instance is stopped/started.

---

## 6. Wire up the Nginx reverse proxy

Install the server block shipped in the repo and restart Nginx:

```bash
sudo cp deploy/nginx-ronway.conf /opt/bitnami/nginx/conf/server_blocks/ronway.conf
# edit the server_name in that file to your real subdomain first:
sudo nano /opt/bitnami/nginx/conf/server_blocks/ronway.conf
sudo /opt/bitnami/ctlscript.sh restart nginx
```

Test over plain HTTP through Nginx:

```bash
curl http://ronway-api.bpxai.com/api/health
```

---

## 7. Enable HTTPS (Let's Encrypt via bncert)

```bash
sudo /opt/bitnami/bncert-tool
```

Enter your domain(s) when prompted, accept the HTTP→HTTPS redirect, and it
configures the certificate **plus automatic renewal**. Then:

```bash
curl https://ronway-api.bpxai.com/api/health
```

---

## 8. Lock down the firewall

In the Lightsail console → instance → **Networking** → IPv4 Firewall:

- **Keep:** SSH (22), HTTP (80), HTTPS (443).
- **Do NOT add 3001.** The scanner is loopback-only; only Nginx talks to it.
  Keeping 3001 closed is also what makes the `X-Forwarded-For` client IP
  trustworthy (only the local proxy can set it).

---

## 9. Point the frontend at it

Your site already sends `Origin: https://bpxai.com`, which is on the API's
CORS allowlist, so the browser call just works:

```js
const res = await fetch("https://ronway-api.bpxai.com/api/scan", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ target: "koleenbp.com" }),
});
const report = await res.json(); // free-tier PublicScanReport
```

History/aggregation for your dashboard:

```
GET https://ronway-api.bpxai.com/api/sites              # per-site scan counts
GET https://ronway-api.bpxai.com/api/scans              # all scans
GET https://ronway-api.bpxai.com/api/scans/koleenbp.com # one site's history
```

---

## Operations

**View / inspect the scan database:**

```bash
docker compose exec ronway sh -c 'ls -la /data'
# query it (sqlite3 inside a throwaway container):
docker run --rm -v ronway-scanner_ronway_data:/data nouchka/sqlite3 \
  /data/ronway.db "SELECT target_domain, COUNT(*) FROM scans GROUP BY target_domain;"
```

**Update to the latest code:**

```bash
cd ~/ronway-scanner && git pull
docker compose up -d --build         # data volume is preserved
```

**Back up scan history:**

```bash
docker run --rm -v ronway-scanner_ronway_data:/data -v "$PWD":/backup \
  busybox cp /data/ronway.db /backup/ronway-backup-$(date +%F).db
```

Or snapshot the whole instance/disk from the Lightsail **Snapshots** tab.

---

## Security checklist

- [ ] Port 3001 is **not** open in the Lightsail firewall (only 22/80/443).
- [ ] HTTPS is active and redirects HTTP (bncert).
- [ ] Consider Cloudflare in front of the subdomain for DDoS + extra rate limiting.
- [ ] The history endpoints (`/api/scans`, `/api/sites`) are currently public.
      They expose scanned **domains + scores** (never client IPs), but if you
      want them private, gate them with an admin token before launch.

---

## Costs (rough, ap-southeast-1)

| Item                           | $/mo                                  |
| ------------------------------ | ------------------------------------- |
| Lightsail 512 MB instance      | ~$5.00 (flat, includes 1 TB transfer) |
| Static IP (attached)           | $0                                    |
| HTTPS (bncert / Let's Encrypt) | $0                                    |
| **Total**                      | **~$5/mo**                            |
