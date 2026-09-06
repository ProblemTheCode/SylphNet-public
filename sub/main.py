#!/usr/bin/env python3
"""SubV2ray - Professional V2Ray config health checker with Iranian date naming"""

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, quote, unquote

import jdatetime


CHANNEL_NAME = "SylphNet"

IRAN_TEST_SCRIPT = r"""#!/bin/bash
ACTION="$1"
HOST="$2"
PORT="$3"

case "$ACTION" in
  latency)
    start=$(date +%s%N)
    timeout 5 bash -c "echo > /dev/tcp/$HOST/$PORT" 2>/dev/null
    result=$?
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    if [ $result -eq 0 ]; then echo "$ms"; else echo "-1"; fi
    ;;
  download)
    bytes=$(timeout 15 curl -s -o /dev/null -w '%{size_download}' "http://speedtest.tele2.net/1MB.zip" 2>/dev/null)
    if [ -z "$bytes" ]; then bytes=0; fi
    echo "$bytes"
    ;;
  internet)
    g=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' "https://www.google.com" 2>/dev/null)
    t=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' "https://api.telegram.org" 2>/dev/null)
    echo "${g:-0}|${t:-0}"
    ;;
  test)
    echo "SSH_OK"
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
    network: str = "tcp"
    security: str = "auto"
    sni: str = ""
    host: str = ""
    path: str = ""
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
    download_speed_kbps: float = 0.0
    internet_ok: bool = False
    healthy: bool = False
    error: str = ""


class ConfigParser:
    @staticmethod
    def decode_base64(data: str) -> str:
        data = data.strip()
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        try:
            return base64.b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def extract_remark(fragment: str) -> str:
        if not fragment:
            return ""
        remark = unquote(fragment.lstrip("#"))
        remark = re.sub(r"[\U0001F1E0-\U0001F1FF]{2}", "", remark)
        remark = re.sub(r"[|/\\\-]", " ", remark).strip()
        remark = re.sub(r"\s+", " ", remark)
        return remark

    @staticmethod
    def parse_vmess(link: str) -> Optional[V2RayConfig]:
        try:
            b64 = link.replace("vmess://", "")
            decoded = ConfigParser.decode_base64(b64)
            if not decoded:
                return None
            config = json.loads(decoded)
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="vmess",
                address=config.get("add", ""),
                port=int(config.get("port", 443)),
                uuid=config.get("id", ""),
                network=config.get("net", "tcp"),
                sni=config.get("sni", ""),
                host=config.get("host", ""),
                path=config.get("path", ""),
                config_type="vmess",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_vless(link: str) -> Optional[V2RayConfig]:
        try:
            parsed = urlparse(link)
            if parsed.scheme != "vless":
                return None
            params = parse_qs(parsed.query)
            sni = params.get("sni", [""])[0]
            host = params.get("host", [""])[0]
            pbk = params.get("pbk", [""])[0]
            security = params.get("security", ["auto"])[0]
            config_type = "reality" if (pbk or "reality" in security) else "vless"
            return V2RayConfig(
                raw=link, protocol="vless",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                uuid=parsed.username or "",
                network=params.get("type", ["tcp"])[0],
                security=security,
                sni=sni or host or parsed.hostname or "",
                host=host or parsed.hostname or "",
                path=params.get("path", [""])[0],
                config_type=config_type,
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_trojan(link: str) -> Optional[V2RayConfig]:
        try:
            parsed = urlparse(link)
            if parsed.scheme != "trojan":
                return None
            params = parse_qs(parsed.query)
            sni = params.get("sni", [""])[0]
            host = params.get("host", [""])[0]
            return V2RayConfig(
                raw=link, protocol="trojan",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                uuid=parsed.username or "",
                sni=sni or host or parsed.hostname or "",
                host=host or parsed.hostname or "",
                path=params.get("path", [""])[0],
                config_type="trojan",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_shadowsocks(link: str) -> Optional[V2RayConfig]:
        try:
            if not link.startswith("ss://"):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="ss",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                config_type="ss",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_hysteria2(link: str) -> Optional[V2RayConfig]:
        try:
            if not link.startswith(("hysteria2://", "hy2://")):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="hysteria2",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                config_type="hysteria2",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_tuic(link: str) -> Optional[V2RayConfig]:
        try:
            if not link.startswith("tuic://"):
                return None
            parsed = urlparse(link)
            return V2RayConfig(
                raw=link, protocol="tuic",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                config_type="tuic",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_subscription(content: str) -> List[V2RayConfig]:
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
                config = ConfigParser.parse_shadowsocks(line)
            elif line.startswith(("hysteria2://", "hy2://")):
                config = ConfigParser.parse_hysteria2(line)
            elif line.startswith("tuic://"):
                config = ConfigParser.parse_tuic(line)
            if config and config.is_valid:
                configs.append(config)
        return configs


class HealthChecker:
    """Test V2Ray configs through Iranian SSH server"""

    SCRIPT_PATH = "/tmp/subv2ray_test.sh"

    def __init__(self, ssh_host, ssh_port, ssh_username, ssh_key_path, max_latency_ms=4000, test_file_url="http://speedtest.tele2.net/1MB.zip"):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_key_path = os.path.expanduser(ssh_key_path)
        self.max_latency_ms = max_latency_ms
        self.test_file_url = test_file_url

    def _ssh_base(self):
        return [
            "ssh", "-i", self.ssh_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            "-p", str(self.ssh_port),
            f"{self.ssh_username}@{self.ssh_host}",
        ]

    def _scp_to_server(self, local_content, remote_path):
        """Write content to remote file via cat"""
        cmd = self._ssh_base() + [f"cat > {remote_path}"]
        result = subprocess.run(cmd, input=local_content, capture_output=True, text=True, timeout=15)
        return result.returncode == 0

    def _setup_script(self):
        """Upload test script to server"""
        print(f"[INFO] Uploading test script to {self.ssh_host}...")
        ok = self._scp_to_server(IRAN_TEST_SCRIPT, self.SCRIPT_PATH)
        if not ok:
            print("[ERROR] Failed to upload test script")
            sys.exit(1)
        self._ssh_cmd(f"chmod +x {self.SCRIPT_PATH}")

    def _ssh_cmd(self, command, timeout=30):
        cmd = self._ssh_base() + [command]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip(), result.returncode
        except Exception as e:
            return str(e), 1

    def _run_script(self, action, host="", port="", timeout=20):
        """Run the test script on the Iranian server"""
        cmd = f"{self.SCRIPT_PATH} {action} {host} {port}"
        output, code = self._ssh_cmd(cmd, timeout=timeout)
        return output, code

    def _measure_latency(self, host, port=443):
        output, code = self._run_script("latency", host, str(port), timeout=10)
        try:
            ms = float(output.strip().split("\n")[-1])
            return ms if ms >= 0 else -1.0
        except Exception:
            return -1.0

    def _test_download(self):
        output, code = self._run_script("download", timeout=20)
        try:
            bytes_down = float(output.strip())
            speed_kbps = (bytes_down * 8) / 15000 if bytes_down > 0 else 0
            return speed_kbps, bytes_down >= 1024 * 1024
        except Exception:
            return -1.0, False

    def _test_internet(self):
        output, code = self._run_script("internet", timeout=15)
        try:
            parts = output.strip().split("|")
            g = parts[0].strip() in ("200", "301", "302")
            t = parts[1].strip() in ("200", "301", "302") if len(parts) > 1 else False
            return g or t
        except Exception:
            return False

    def check_config(self, config):
        result = HealthResult(config=config)
        try:
            latency = self._measure_latency(config.address, config.port)
            result.latency_ms = latency
            config.latency_ms = latency
            if latency < 0 or latency > self.max_latency_ms:
                result.error = f"High latency: {latency:.0f}ms"
                return result
            result.healthy = True
            return result
        except Exception as e:
            result.error = str(e)
            return result

    def check_configs(self, configs):
        results = []

        self._setup_script()

        print("[INFO] Testing SSH connection...")
        out, code = self._run_script("test", timeout=10)
        if code == 0 and "SSH_OK" in out:
            print("[INFO] SSH OK - testing from Iran")
        else:
            print(f"[ERROR] SSH FAILED: {out[:200]}")
            sys.exit(1)

        print("[INFO] Testing download speed from Iran...")
        speed, dl_ok = self._test_download()
        if dl_ok:
            print(f"[INFO] Download: {speed:.0f} kbps - OK")
        else:
            print(f"[WARNING] Download: {speed:.0f} kbps - may affect results")

        print("[INFO] Testing internet access from Iran...")
        inet_ok = self._test_internet()
        print(f"[INFO] Internet: {'OK' if inet_ok else 'BLOCKED (expected for some sites)'}")

        print(f"\n[INFO] Testing {len(configs)} configs for TCP reachability from Iran...")
        for i, config in enumerate(configs):
            print(f"[{i+1}/{len(configs)}] {config.config_type}://{config.address}:{config.port} ...", end=" ", flush=True)
            result = self.check_config(config)
            results.append(result)
            if result.healthy:
                print(f"OK | {result.latency_ms:.0f}ms")
            else:
                print(f"FAIL | {result.error}")

        healthy = [r for r in results if r.healthy]
        print(f"\n[RESULT] {len(healthy)}/{len(configs)} configs reachable from Iran")
        return results


class SubscriptionManager:
    @staticmethod
    def fetch_subscription(url):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)
        content = response.read().decode("utf-8", errors="ignore").strip()

        lines = content.split("\n")
        protocols = ("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
        if any(l.strip().startswith(protocols) for l in lines):
            return content

        decoded = ConfigParser.decode_base64(content)
        if decoded:
            decoded_lines = decoded.split("\n")
            if any(l.strip().startswith(protocols) for l in decoded_lines):
                return decoded
        return content

    @staticmethod
    def get_iranian_date():
        now = jdatetime.date.today()
        return f"{now.year:04d}-{now.month:02d}-{now.day:02d}"

    @staticmethod
    def rename_configs(configs):
        date_str = SubscriptionManager.get_iranian_date()
        sorted_configs = sorted(configs, key=lambda c: c.latency_ms if c.latency_ms >= 0 else 99999)
        for i, config in enumerate(sorted_configs, 1):
            new_remark = f"@{CHANNEL_NAME} | {date_str} #{i}"
            if config.raw.startswith("vmess://"):
                config.raw = SubscriptionManager._update_vmess_remark(config.raw, new_remark)
            else:
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            config.remark = new_remark
        return sorted_configs

    @staticmethod
    def _update_vmess_remark(raw, new_remark):
        try:
            b64 = raw.replace("vmess://", "")
            config = json.loads(ConfigParser.decode_base64(b64))
            config["ps"] = new_remark
            new_b64 = base64.b64encode(json.dumps(config).encode()).decode()
            return f"vmess://{new_b64}"
        except Exception:
            return raw

    @staticmethod
    def _update_uri_remark(raw, new_remark):
        try:
            encoded = quote(new_remark, safe="")
            base = raw.rsplit("#", 1)[0] if "#" in raw else raw
            return f"{base}#{encoded}"
        except Exception:
            return raw

    @staticmethod
    def generate_base64_subscription(configs):
        content = "\n".join(c.raw for c in configs)
        return base64.b64encode(content.encode()).decode()

    @staticmethod
    def save_subscription(configs, output_path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        b64 = SubscriptionManager.generate_base64_subscription(configs)
        output_path.write_text(b64, encoding="utf-8")
        print(f"[INFO] Saved {len(configs)} configs to {output_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SubV2ray Health Checker")
    parser.add_argument("--sub-url", required=True, help="Subscription URL(s), comma-separated")
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--max-latency", type=int, default=4000)
    parser.add_argument("--output", default="sub.txt")
    parser.add_argument("--max-configs", type=int, default=30)
    args = parser.parse_args()

    urls = [u.strip() for u in args.sub_url.split(",") if u.strip()]
    all_configs = []
    seen = set()

    for url in urls:
        print(f"[INFO] Fetching from {url}")
        try:
            content = SubscriptionManager.fetch_subscription(url)
            configs = ConfigParser.parse_subscription(content)
            print(f"[INFO]   -> {len(configs)} configs found")
            for c in configs:
                key = f"{c.address}:{c.port}"
                if key not in seen:
                    seen.add(key)
                    all_configs.append(c)
        except Exception as e:
            print(f"[WARNING] Failed: {e}")

    configs = all_configs[:args.max_configs]
    print(f"[INFO] Total unique: {len(all_configs)}, testing top {len(configs)}")

    if not configs:
        print("[ERROR] No configs found", file=sys.stderr)
        sys.exit(1)

    checker = HealthChecker(
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        max_latency_ms=args.max_latency,
    )
    results = checker.check_configs(configs)
    healthy = [r.config for r in results if r.healthy]

    if healthy:
        renamed = SubscriptionManager.rename_configs(healthy)
        date_str = SubscriptionManager.get_iranian_date()
        print(f"\n[RENAMED] @{CHANNEL_NAME} | {date_str} #N (sorted by ping)")
        for c in renamed:
            print(f"  {c.remark} | {c.latency_ms:.0f}ms")

    SubscriptionManager.save_subscription(healthy, Path(args.output))

    if not healthy:
        print("[WARNING] No healthy configs found")
    else:
        print(f"[SUCCESS] {len(healthy)} healthy configs saved")


if __name__ == "__main__":
    main()
