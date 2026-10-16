#!/usr/bin/env python3
"""SylphNet Tier-1 aggregator — stdlib only, no secrets, no SSH.

Fetches upstream community subscriptions, dedupes, Jalali-renames,
writes base64 sub.txt + plain sub_plain.txt.
Guards: never writes empty output; exits non-zero below --min-configs.
"""
import argparse
import base64
import datetime
import json
import re
import sys
import urllib.request
from urllib.parse import quote

SOURCES = [
    "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
]
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://",
           "hysteria2://", "hy2://", "anytls://")


def gregorian_to_jalali(gy, gm, gd):
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = (355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100
            + (gy2 + 399) // 400 + g_d_m[gm - 1] + gd)
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm, jd = 1 + days // 31, 1 + days % 31
    else:
        jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
    return jy, jm, jd


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode(
        "utf-8", errors="ignore").strip()


def as_plain(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if any(l.startswith(SCHEMES) for l in lines):
        return text
    compact = re.sub(r"\s+", "", text)
    try:
        pad = "=" * (-len(compact) % 4)
        dec = base64.b64decode(compact + pad).decode("utf-8", errors="ignore")
        if any(l.strip().startswith(SCHEMES)
               for l in dec.splitlines() if l.strip()):
            return dec
    except Exception:
        pass
    return text


def rename(raw_list, date):
    out = []
    for i, raw in enumerate(raw_list, 1):
        remark = f"@SylphNet | {date} #{i}"
        if raw.startswith("vmess://"):
            try:
                b = raw[8:].strip()
                b += "=" * (-len(b) % 4)
                obj = json.loads(base64.b64decode(b).decode())
                obj["ps"] = remark
                raw = ("vmess://" + base64.b64encode(
                    json.dumps(obj, ensure_ascii=False).encode()).decode())
            except Exception:
                raw = f"{raw.split('#')[0]}#{quote(remark, safe='')}"
        else:
            base = raw.rsplit("#", 1)[0] if "#" in raw else raw
            raw = f"{base}#{quote(remark, safe='')}"
        out.append(raw)
    return out


def main():
    p = argparse.ArgumentParser(description="SylphNet Tier-1 aggregator")
    p.add_argument("--out", default="./out", help="output directory")
    p.add_argument("--min-configs", type=int, default=20)
    args = p.parse_args()

    import os
    seen, configs, failed = set(), [], []
    for url in SOURCES:
        try:
            text = as_plain(fetch(url))
            n = 0
            for line in text.splitlines():
                line = line.strip()
                if line.startswith(SCHEMES) and line not in seen:
                    seen.add(line)
                    configs.append(line)
                    n += 1
            print(f"[FETCH] {url} -> {n} new ({len(configs)} total)")
        except Exception as e:
            failed.append(url)
            print(f"[WARN] {url}: {e}", file=sys.stderr)

    print(f"[TOTAL] {len(configs)} unique configs, {len(failed)} failed sources")
    if len(configs) < args.min_configs:
        print(f"[GUARD] below --min-configs={args.min_configs}, NOT writing",
              file=sys.stderr)
        sys.exit(2)

    t = datetime.date.today()
    jy, jm, jd = gregorian_to_jalali(t.year, t.month, t.day)
    jalali = f"{jy:04d}-{jm:02d}-{jd:02d}"
    utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    renamed = rename(configs, jalali)
    header = (f"#profile-title: SylphNet | {jalali}\n"
              f"#profile-update-interval: 1\n"
              f"#last-update: {utc}\n"
              f"#configs: {len(renamed)} aggregated\n")
    plain = header + "\n".join(renamed) + "\n"
    b64 = base64.b64encode(plain.encode()).decode()

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "sub.txt"), "w", encoding="utf-8") as f:
        f.write(b64)
    with open(os.path.join(args.out, "sub_plain.txt"), "w", encoding="utf-8") as f:
        f.write(plain)
    print(f"[SAVE] {len(renamed)} configs -> {args.out}/sub.txt + sub_plain.txt")


if __name__ == "__main__":
    main()
