#!/usr/bin/env python3
"""SubV2ray - V2Ray config health checker using Xray kernel on Iranian server"""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, quote, unquote

import jdatetime

CHANNEL_NAME = "SylphNet"
XRAY_REMOTE = "/tmp/xray"
GEOIP_REMOTE = "/tmp/geoip.dat"
GEOSITE_REMOTE = "/tmp/geosite.dat"
PROXY_PORT = 10809
TEST_SCRIPT = r"""#!/bin/bash
ACTION="$1"
case "$ACTION" in
  start)
    CFG="$2"
    pkill -u $(whoami) -f "xray run" 2>/dev/null
    sleep 1
    /tmp/xray run -config "$CFG" &>/tmp/xray_run.log &
    echo $! > /tmp/xray.pid
    sleep 2
    kill -0 $(cat /tmp/xray.pid) 2>/dev/null && echo "STARTED" || echo "FAILED"
    ;;
  test)
    g1=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' --proxy http://127.0.0.1:10809 "http://ifconfig.me" 2>/dev/null)
    g2=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' --proxy http://127.0.0.1:10809 "https://www.google.com" 2>/dev/null)
    t1=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' --proxy http://127.0.0.1:10809 "http://api.telegram.org" 2>/dev/null)
    t2=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' --proxy http://127.0.0.1:10809 "https://api.telegram.org" 2>/dev/null)
    echo "${g1:-0}|${g2:-0}|${t1:-0}|${t2:-0}"
    ;;
  latency)
    start=$(date +%s%N)
    timeout 5 curl -s -o /dev/null --proxy http://127.0.0.1:10809 "http://ifconfig.me" 2>/dev/null
    result=$?
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    if [ $result -eq 0 ] || [ $ms -lt 8000 ]; then echo "$ms"; else echo "-1"; fi
    ;;
  stop)
    if [ -f /tmp/xray.pid ]; then
      kill $(cat /tmp/xray.pid) 2>/dev/null
      rm -f /tmp/xray.pid
    fi
    pkill -u $(whoami) -f "xray run" 2>/dev/null
    echo "STOPPED"
    ;;
  check)
    kill -0 $(cat /tmp/xray.pid 2>/dev/null) 2>/dev/null && echo "RUNNING" || echo "STOPPED"
    ;;
esac
"""


@dataclass
class V2RayConfig:
    raw: str
    protocol: str = "unknown"
    address: str = ""
    port: int = 443
    uuid: str = ""
    password: str = ""
    network: str = "tcp"
    security: str = "auto"
    sni: str = ""
    host: str = ""
    path: str = ""
    flow: str = ""
    fp: str = ""
    pbk: str = ""
    sid: str = ""
    config_type: str = "unknown"
    remark: str = ""
    latency_ms: float = -1.0

    @property
    def is_valid(self) -> bool:
        return bool(self.address and self.port)


@dataclass
class HealthResult:
    config: V2RayConfig
    latency_ms: float = 0.0
    google_ok: bool = False
    telegram_ok: bool = False
    healthy: bool = False
    error: str = ""


class ConfigParser:
    @staticmethod
    def decode_base64(data):
        data = data.strip()
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        try:
            return base64.b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def extract_remark(fragment):
        if not fragment:
            return ""
        remark = unquote(fragment.lstrip("#"))
        remark = re.sub(r"[\U0001F1E0-\U0001F1FF]{2}", "", remark)
        remark = re.sub(r"[|/\\\-]", " ", remark).strip()
        return re.sub(r"\s+", " ", remark)

    @staticmethod
    def parse_vless(link):
        try:
            parsed = urlparse(link)
            if parsed.scheme != "vless":
                return None
            params = parse_qs(parsed.query)
            sec = params.get("security", ["auto"])[0]
            fp = params.get("fp", [""])[0]
            pbk = params.get("pbk", [""])[0]
            sid = params.get("sid", [""])[0]
            ct = "reality" if (pbk or sec == "reality") else sec
            flow_val = params.get("flow", [""])[0]
            if not flow_val and ct == "reality":
                flow_val = "xtls-rprx-vision"
            return V2RayConfig(
                raw=link, protocol="vless",
                address=parsed.hostname or "", port=parsed.port or 443,
                uuid=parsed.username or "",
                network=params.get("type", ["tcp"])[0],
                security=sec, sni=params.get("sni", [""])[0] or params.get("host", [""])[0] or parsed.hostname or "",
                host=params.get("host", [""])[0] or parsed.hostname or "",
                path=params.get("path", [""])[0],
                flow=flow_val, fp=fp, pbk=pbk, sid=sid,
                config_type=ct, remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_vmess(link):
        try:
            b64 = link.replace("vmess://", "")
            decoded = ConfigParser.decode_base64(b64)
            if not decoded:
                return None
            c = json.loads(decoded)
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="vmess",
                address=c.get("add", ""), port=int(c.get("port", 443)),
                uuid=c.get("id", ""), network=c.get("net", "tcp"),
                security=c.get("tls", ""), sni=c.get("sni", ""),
                host=c.get("host", ""), path=c.get("path", ""),
                fp=c.get("fp", ""), config_type="vmess",
                remark=c.get("ps") or ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_trojan(link):
        try:
            parsed = urlparse(link)
            if parsed.scheme != "trojan":
                return None
            params = parse_qs(parsed.query)
            return V2RayConfig(
                raw=link, protocol="trojan",
                address=parsed.hostname or "", port=parsed.port or 443,
                uuid=parsed.username or "",
                sni=params.get("sni", [""])[0] or parsed.hostname or "",
                host=params.get("host", [""])[0],
                path=params.get("path", [""])[0],
                config_type="trojan",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_ss(link):
        try:
            if not link.startswith("ss://"):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="ss",
                address=parsed.hostname or "", port=parsed.port or 443,
                config_type="ss",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_hy2(link):
        try:
            if not link.startswith(("hysteria2://", "hy2://")):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="hysteria2",
                address=parsed.hostname or "", port=parsed.port or 443,
                password=parsed.username or "",
                config_type="hysteria2",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_tuic(link):
        try:
            if not link.startswith("tuic://"):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="tuic",
                address=parsed.hostname or "", port=parsed.port or 443,
                config_type="tuic",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_subscription(content):
        configs = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            config = None
            if line.startswith("vmess://"):
                config = ConfigParser.parse_vmess(line)
            elif line.startswith("vless://"):
                config = ConfigParser.parse_vless(line)
            elif line.startswith("trojan://"):
                config = ConfigParser.parse_trojan(line)
            elif line.startswith("ss://"):
                config = ConfigParser.parse_ss(line)
            elif line.startswith(("hysteria2://", "hy2://")):
                config = ConfigParser.parse_hy2(line)
            elif line.startswith("tuic://"):
                config = ConfigParser.parse_tuic(line)
            if config and config.is_valid:
                configs.append(config)
        return configs


class XrayConfigGenerator:
    @staticmethod
    def generate(cfg, port=PROXY_PORT):
        if cfg.protocol == "vless":
            return XrayConfigGenerator._gen_vless(cfg, port)
        elif cfg.protocol == "vmess":
            return XrayConfigGenerator._gen_vmess(cfg, port)
        elif cfg.protocol == "trojan":
            return XrayConfigGenerator._gen_trojan(cfg, port)
        elif cfg.protocol == "ss":
            return XrayConfigGenerator._gen_ss(cfg, port)
        return None

    @staticmethod
    def _base(port):
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": port, "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"timeout": 0, "allowTransparent": False, "userLevel": 0},
                "tag": "http-in"
            }],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct"
            }],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "direct"
                }]
            }
        }

    @staticmethod
    def _stream(cfg):
        s = {"network": cfg.network}
        sni = cfg.sni or cfg.host or cfg.address
        fp = cfg.fp or "chrome"
        alpn_val = "h2,http/1.1"

        if cfg.security in ("reality",) or cfg.pbk:
            s["security"] = "reality"
            s["realitySettings"] = {
                "serverName": sni,
                "allowInsecure": True,
                "fingerprint": fp,
                "alpn": alpn_val.split(","),
                "show": False,
                "publicKey": cfg.pbk,
                "shortId": cfg.sid,
                "spiderX": cfg.path or "/",
            }
        elif cfg.security == "tls":
            s["security"] = "tls"
            s["tlsSettings"] = {
                "serverName": sni, "fingerprint": fp,
                "allowInsecure": True,
                "alpn": alpn_val.split(","),
            }
        else:
            s["security"] = "none"

        if cfg.network == "ws":
            s["wsSettings"] = {"path": cfg.path, "headers": {"Host": cfg.host} if cfg.host else {}}
        elif cfg.network == "grpc":
            s["grpcSettings"] = {"serviceName": cfg.path.lstrip("/"), "multiMode": True}
        elif cfg.network == "h2":
            s["httpSettings"] = {"path": cfg.path, "host": [cfg.host]}
        elif cfg.network == "xhttp":
            s["xhttpSettings"] = {"mode": "auto", "path": cfg.path or "/"}
        elif cfg.network == "tcp":
            s["tcpSettings"] = {"header": {"type": "none"}}
        return s

    @staticmethod
    def _gen_vless(cfg, port):
        c = XrayConfigGenerator._base(port)
        user = {"id": cfg.uuid, "encryption": "none"}
        if cfg.flow:
            user["flow"] = cfg.flow
        c["outbounds"] = [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": cfg.address, "port": cfg.port, "users": [user]}]},
            "streamSettings": XrayConfigGenerator._stream(cfg),
        }]
        return c

    @staticmethod
    def _gen_vmess(cfg, port):
        c = XrayConfigGenerator._base(port)
        c["outbounds"] = [{
            "protocol": "vmess",
            "settings": {"vnext": [{"address": cfg.address, "port": cfg.port,
                                     "users": [{"id": cfg.uuid, "alterId": 0}]}]},
            "streamSettings": XrayConfigGenerator._stream(cfg),
        }]
        return c

    @staticmethod
    def _gen_trojan(cfg, port):
        c = XrayConfigGenerator._base(port)
        c["outbounds"] = [{
            "protocol": "trojan",
            "settings": {"servers": [{"address": cfg.address, "port": cfg.port,
                                       "password": cfg.uuid}]},
            "streamSettings": XrayConfigGenerator._stream(cfg),
        }]
        return c

    @staticmethod
    def _gen_ss(cfg, port):
        c = XrayConfigGenerator._base(port)
        c["outbounds"] = [{
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": cfg.address, "port": cfg.port}]},
        }]
        return c


class HealthChecker:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_key, max_latency=4000):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key = os.path.expanduser(ssh_key)
        self.max_latency = max_latency

    def _ssh_base(self):
        return ["ssh", "-i", self.ssh_key, "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                "-p", str(self.ssh_port), f"{self.ssh_user}@{self.ssh_host}"]

    def _ssh(self, cmd, timeout=30):
        result = subprocess.run(self._ssh_base() + [cmd], capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.returncode

    def _run_script(self, action, arg="", timeout=20):
        cmd = f"/tmp/subv2ray_test.sh {action} {arg}"
        return self._ssh(cmd, timeout)

    def setup(self):
        print(f"[INFO] Setting up Xray on {self.ssh_host}...")
        ok, _ = self._ssh(f"test -x {XRAY_REMOTE} && echo OK || echo MISSING")
        if "MISSING" in ok or not ok:
            print("[INFO] Uploading Xray binary...")
            subprocess.run(["scp", "-i", self.ssh_key, "-P", str(self.ssh_port),
                            "-o", "StrictHostKeyChecking=no",
                            "/tmp/xray_dir/xray", f"{self.ssh_user}@{self.ssh_host}:{XRAY_REMOTE}"],
                           timeout=120)
            self._ssh(f"chmod +x {XRAY_REMOTE}")
        print("[INFO] Uploading geo data...")
        for f in ["geoip.dat", "geosite.dat"]:
            subprocess.run(["scp", "-i", self.ssh_key, "-P", str(self.ssh_port),
                            "-o", "StrictHostKeyChecking=no",
                            f"/tmp/xray_dir/{f}", f"{self.ssh_user}@{self.ssh_host}:/tmp/{f}"],
                           timeout=60)
        print("[INFO] Uploading test script...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tmp:
            tmp.write(TEST_SCRIPT)
            tmp_path = tmp.name
        subprocess.run(["scp", "-i", self.ssh_key, "-P", str(self.ssh_port),
                        "-o", "StrictHostKeyChecking=no",
                        tmp_path, f"{self.ssh_user}@{self.ssh_host}:/tmp/subv2ray_test.sh"],
                       timeout=15)
        os.unlink(tmp_path)
        self._ssh("chmod +x /tmp/subv2ray_test.sh")
        print("[INFO] Setup complete")

    def test_config(self, cfg):
        result = HealthResult(config=cfg)
        xray_cfg = XrayConfigGenerator.generate(cfg)
        if not xray_cfg:
            result.error = f"Unsupported protocol: {cfg.protocol}"
            return result

        cfg_json = json.dumps(xray_cfg)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(cfg_json)
            tmp_path = f.name
        subprocess.run(["scp", "-i", self.ssh_key, "-P", str(self.ssh_port),
                        "-o", "StrictHostKeyChecking=no",
                        tmp_path, f"{self.ssh_user}@{self.ssh_host}:/tmp/xray_cfg.json"],
                       timeout=10)
        os.unlink(tmp_path)

        out, code = self._run_script("start", "/tmp/xray_cfg.json", timeout=10)
        if "STARTED" not in out:
            result.error = "Xray failed to start"
            self._run_script("stop", timeout=5)
            return result

        out, code = self._run_script("test", timeout=30)
        self._run_script("stop", timeout=5)

        try:
            parts = out.strip().split("|")
            g_http = parts[0].strip() if len(parts) > 0 else "0"
            g_https = parts[1].strip() if len(parts) > 1 else "0"
            t_http = parts[2].strip() if len(parts) > 2 else "0"
            t_https = parts[3].strip() if len(parts) > 3 else "0"
            result.google_ok = g_http in ("200", "301", "302") or g_https in ("200", "301", "302")
            result.telegram_ok = t_http in ("200", "301", "302") or t_https in ("200", "301", "302")
        except Exception:
            result.error = f"Bad test output: {out[:50]}"
            return result

        if result.google_ok or result.telegram_ok:
            out2, _ = self._run_script("latency", timeout=15)
            try:
                result.latency_ms = float(out2.strip())
            except Exception:
                result.latency_ms = 0
            result.healthy = True
        else:
            result.error = f"Proxy fail: g_http={g_http} g_https={g_https} t_http={t_http} t_https={t_https}"

        return result

    def check_configs(self, configs):
        self.setup()
        print("\n[INFO] Testing SSH connection...")
        out, _ = self._run_script("check", timeout=10)
        print(f"[INFO] SSH OK, testing {len(configs)} configs with Xray kernel...\n")

        results = []
        for i, cfg in enumerate(configs):
            proto = cfg.config_type
            print(f"[{i+1}/{len(configs)}] {proto}://{cfg.address}:{cfg.port} ...", end=" ", flush=True)
            r = self.test_config(cfg)
            results.append(r)
            if r.healthy:
                print(f"OK | {r.latency_ms:.0f}ms | G={'Y' if r.google_ok else 'N'} T={'Y' if r.telegram_ok else 'N'}")
            else:
                print(f"FAIL | {r.error}")

        healthy = [r for r in results if r.healthy]
        print(f"\n[RESULT] {len(healthy)}/{len(configs)} configs WORKING through Xray from Iran")
        return results


class SubscriptionManager:
    @staticmethod
    def fetch(url):
        headers = {"User-Agent": "Mozilla/5.0"}
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)
        content = response.read().decode("utf-8", errors="ignore").strip()
        protocols = ("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
        if any(l.strip().startswith(protocols) for l in content.split("\n")):
            return content
        decoded = ConfigParser.decode_base64(content)
        if decoded and any(l.strip().startswith(protocols) for l in decoded.split("\n")):
            return decoded
        return content

    @staticmethod
    def iranian_date():
        now = jdatetime.date.today()
        return f"{now.year:04d}-{now.month:02d}-{now.day:02d}"

    @staticmethod
    def rename(configs):
        date_str = SubscriptionManager.iranian_date()
        sorted_c = sorted(configs, key=lambda c: c.latency_ms if c.latency_ms >= 0 else 99999)
        for i, c in enumerate(sorted_c, 1):
            new_remark = f"@{CHANNEL_NAME} | {date_str} #{i}"
            if c.raw.startswith("vmess://"):
                try:
                    b64 = c.raw.replace("vmess://", "")
                    obj = json.loads(ConfigParser.decode_base64(b64))
                    obj["ps"] = new_remark
                    c.raw = f"vmess://{base64.b64encode(json.dumps(obj).encode()).decode()}"
                except Exception:
                    pass
            else:
                encoded = quote(new_remark, safe="")
                base = c.raw.rsplit("#", 1)[0] if "#" in c.raw else c.raw
                c.raw = f"{base}#{encoded}"
            c.remark = new_remark
        return sorted_c

    @staticmethod
    def save(configs, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(c.raw for c in configs)
        b64 = base64.b64encode(content.encode()).decode()
        path.write_text(b64, encoding="utf-8")
        print(f"[INFO] Saved {len(configs)} configs to {path}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sub-url", required=True)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--max-latency", type=int, default=4000)
    parser.add_argument("--output", default="sub.txt")
    parser.add_argument("--max-configs", type=int, default=20)
    args = parser.parse_args()

    urls = [u.strip() for u in args.sub_url.split(",") if u.strip()]
    all_configs, seen = [], set()
    for url in urls:
        print(f"[INFO] Fetching from {url}")
        try:
            content = SubscriptionManager.fetch(url)
            configs = ConfigParser.parse_subscription(content)
            print(f"[INFO]   -> {len(configs)} configs")
            for c in configs:
                key = f"{c.protocol}:{c.address}:{c.port}"
                if key not in seen:
                    seen.add(key)
                    all_configs.append(c)
        except Exception as e:
            print(f"[WARNING] Failed: {e}")

    configs = all_configs[:args.max_configs]
    print(f"[INFO] Unique: {len(all_configs)}, testing: {len(configs)}")

    if not configs:
        print("[ERROR] No configs", file=sys.stderr)
        sys.exit(1)

    checker = HealthChecker(args.ssh_host, args.ssh_port, args.ssh_user, args.ssh_key, args.max_latency)
    results = checker.check_configs(configs)
    healthy = [r.config for r in results if r.healthy]

    if healthy:
        renamed = SubscriptionManager.rename(healthy)
        print(f"\n[RENAMED] @{CHANNEL_NAME} | {SubscriptionManager.iranian_date()} #N")
        for c in renamed:
            print(f"  {c.remark} | {c.latency_ms:.0f}ms")

    SubscriptionManager.save(healthy, Path(args.output))
    print(f"[SUCCESS] {len(healthy)} working configs" if healthy else "[WARNING] No working configs found")


if __name__ == "__main__":
    main()
