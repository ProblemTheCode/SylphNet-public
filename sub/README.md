# SylphNet — V2Ray Health Checker

Automated health checker that fetches community subscription configs, tests them **through Xray kernel on an Iranian server**, and publishes healthy configs.

## How it works

1. Fetch subscription(s) from `SUB_URL` (comma-separated)
2. Parse vless / vmess / trojan / ss configs, deduplicate by raw link
3. Upload + batch-test on the Iranian server via SSH (`/tmp/xray` + `python3`)
   - Each config starts Xray on `127.0.0.1:20809` (http proxy)
   - `curl http://ifconfig.me` through proxy — any HTTP code except `000` = healthy
   - Latency measured via second curl
4. Sort healthy configs by latency, rename to `@SylphNet | YYYY-MM-DD #N` (Jalali)
5. Save base64 subscription to `sub.txt` (and `sub.plain.txt`)

## Repo layout

- `subv2ray-private` (this repo) — checker code + GitHub Actions (every 15 min)
- `SylphNet-public` — public subscription at `sub/sub.txt`

## Secrets required (Actions)

| Secret | Description |
|---|---|
| `SUB_URL` | Subscription URL(s), comma-separated |
| `SSH_HOST` / `SSH_PORT` / `SSH_USER` / `SSH_KEY` | Iranian server |
| `PUBLIC_REPO_TOKEN` | PAT with push to `SylphNet-public` |

## Local run

```bash
pip install -r requirements.txt
python main.py --sub-url "https://example.com/sub.txt" \
  --ssh-host 1.2.3.4 --ssh-port 22 --ssh-user v2raychecker \
  --ssh-key ~/.ssh/subv2ray_key --output sub.txt
# sub.txt is base64; decode: base64 -d sub.txt | head
```

## Subscription

```
https://raw.githubusercontent.com/ProblemTheCode/SylphNet-public/refs/heads/main/sub/sub.txt
```
Base64-encoded, one config per line after decoding. `sub/sub_plain.txt` is plaintext.

## Notes

- Server must have `/tmp/xray` (Xray core) and `python3` on `$PATH`
- Health = proxy returns any HTTP status (200/301/403/503…); only `000` (no route) = fail
- `anytls` / `socks` protocols are skipped (unsupported by Xray)
