#!/usr/bin/env python3
"""SubV2ray - Professional V2Ray config health checker with Iranian date naming"""

import base64
import json
import re
import socket
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, quote, unquote

import jdatetime
import requests
from sshtunnel import SSHTunnelForwarder


CHANNEL_NAME = "SylphNet"


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
    youtube_ok: bool = False
    healthy: bool = False
    error: str = ""


class ConfigParser:
    """Parse V2Ray subscription configs"""

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
                raw=link,
                protocol="vmess",
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
            uuid = parsed.username
            address = parsed.hostname
            port = parsed.port or 443
            params = parse_qs(parsed.query)
            sni = params.get("sni", [""])[0]
            host = params.get("host", [""])[0]
            path = params.get("path", [""])[0]
            security = params.get("security", ["auto"])[0]
            network = params.get("type", ["tcp"])[0]
            pbk = params.get("pbk", [""])[0]
            sid = params.get("sid", [""])[0]
            config_type = "reality" if (pbk or "reality" in security) else "vless"
            return V2RayConfig(
                raw=link,
                protocol="vless",
                address=address,
                port=port,
                uuid=uuid,
                network=network,
                security=security,
                sni=sni or host or address,
                host=host or address,
                path=path,
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
            uuid = parsed.username
            address = parsed.hostname
            port = parsed.port or 443
            params = parse_qs(parsed.query)
            sni = params.get("sni", [""])[0]
            host = params.get("host", [""])[0]
            path = params.get("path", [""])[0]
            return V2RayConfig(
                raw=link,
                protocol="trojan",
                address=address,
                port=port,
                uuid=uuid,
                sni=sni or host or address,
                host=host or address,
                path=path,
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
            address = parsed.hostname
            port = parsed.port or 443
            return V2RayConfig(
                raw=link,
                protocol="ss",
                address=address,
                port=port,
                config_type="ss",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_hysteria2(link: str) -> Optional[V2RayConfig]:
        try:
            if not link.startswith("hysteria2://"):
                return None
            parsed = urlparse(link)
            address = parsed.hostname
            port = parsed.port or 443
            return V2RayConfig(
                raw=link,
                protocol="hysteria2",
                address=address,
                port=port,
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
            address = parsed.hostname
            port = parsed.port or 443
            return V2RayConfig(
                raw=link,
                protocol="tuic",
                address=address,
                port=port,
                config_type="tuic",
                remark=ConfigParser.extract_remark(parsed.fragment),
            )
        except Exception:
            return None

    @staticmethod
    def parse_subscription(content: str) -> List[V2RayConfig]:
        configs = []
        lines = content.strip().split("\n")
        for line in lines:
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
            elif line.startswith("hysteria2://") or line.startswith("hy2://"):
                config = ConfigParser.parse_hysteria2(line)
            elif line.startswith("tuic://"):
                config = ConfigParser.parse_tuic(line)
            if config and config.is_valid:
                configs.append(config)
        return configs


class HealthChecker:
    """Test V2Ray configs through Iranian SSH tunnel"""

    def __init__(
        self,
        ssh_host: str,
        ssh_port: int,
        ssh_username: str,
        ssh_key_path: str,
        max_latency_ms: int = 4000,
        test_file_url: str = "http://speedtest.tele2.net/5MB.zip",
        youtube_url: str = "https://www.youtube.com",
    ):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_key_path = ssh_key_path
        self.max_latency_ms = max_latency_ms
        self.test_file_url = test_file_url
        self.youtube_url = youtube_url
        self.tunnel: Optional[SSHTunnelForwarder] = None

    def _start_tunnel(self) -> bool:
        try:
            self.tunnel = SSHTunnelForwarder(
                (self.ssh_host, self.ssh_port),
                ssh_username=self.ssh_username,
                ssh_pkey=self.ssh_key_path,
                remote_bind_address=("127.0.0.1", 0),
            )
            self.tunnel.start()
            return True
        except Exception as e:
            print(f"[ERROR] SSH tunnel failed: {e}", file=sys.stderr)
            return False

    def _stop_tunnel(self):
        if self.tunnel:
            try:
                self.tunnel.stop()
            except Exception:
                pass
            self.tunnel = None

    def _measure_latency(self, target_host: str, target_port: int = 443) -> float:
        try:
            start = time.time()
            sock = socket.create_connection((target_host, target_port), timeout=10)
            latency = (time.time() - start) * 1000
            sock.close()
            return latency
        except Exception:
            return -1.0

    def _test_download_speed(self) -> tuple:
        try:
            start = time.time()
            proxies = {}
            if self.tunnel:
                proxies = {
                    "http": f"http://127.0.0.1:{self.tunnel.local_bind_port}",
                    "https": f"http://127.0.0.1:{self.tunnel.local_bind_port}",
                }
            response = requests.get(
                self.test_file_url, timeout=60, stream=True, proxies=proxies or None,
            )
            response.raise_for_status()
            total_bytes = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    total_bytes += len(chunk)
            elapsed = time.time() - start
            speed_kbps = (total_bytes * 8) / (elapsed * 1000) if elapsed > 0 else 0
            return speed_kbps, total_bytes >= 5 * 1024 * 1024
        except Exception:
            return -1.0, False

    def _test_youtube(self) -> bool:
        try:
            proxies = {}
            if self.tunnel:
                proxies = {
                    "http": f"http://127.0.0.1:{self.tunnel.local_bind_port}",
                    "https": f"http://127.0.0.1:{self.tunnel.local_bind_port}",
                }
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            response = requests.get(
                self.youtube_url, timeout=30, proxies=proxies, headers=headers, allow_redirects=True,
            )
            return response.status_code == 200
        except Exception:
            return False

    def check_config(self, config: V2RayConfig) -> HealthResult:
        result = HealthResult(config=config)
        if not self._start_tunnel():
            result.error = "SSH tunnel failed"
            return result
        try:
            latency = self._measure_latency(config.address, config.port)
            result.latency_ms = latency
            config.latency_ms = latency
            if latency < 0 or latency > self.max_latency_ms:
                result.error = f"High latency: {latency:.0f}ms"
                return result
            speed, downloaded_ok = self._test_download_speed()
            result.download_speed_kbps = speed
            if not downloaded_ok or speed < 500:
                result.error = f"Slow download: {speed:.0f} kbps"
                return result
            youtube_ok = self._test_youtube()
            result.youtube_ok = youtube_ok
            if not youtube_ok:
                result.error = "YouTube not accessible"
                return result
            result.healthy = True
            return result
        finally:
            self._stop_tunnel()

    def check_configs(self, configs: List[V2RayConfig]) -> List[HealthResult]:
        results = []
        print(f"[INFO] Checking {len(configs)} configs...")
        for i, config in enumerate(configs):
            print(f"[{i+1}/{len(configs)}] Testing {config.config_type}://{config.address}:{config.port} ...")
            result = self.check_config(config)
            results.append(result)
            if result.healthy:
                print(f"  OK | {result.latency_ms:.0f}ms | {result.download_speed_kbps:.0f} kbps")
            else:
                print(f"  FAIL | {result.error}")
        healthy = [r for r in results if r.healthy]
        print(f"\n[RESULT] {len(healthy)}/{len(configs)} configs healthy")
        return results


class SubscriptionManager:
    """Manage subscription feeds and output"""

    @staticmethod
    def fetch_subscription(url: str) -> str:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, timeout=30, headers=headers)
        response.raise_for_status()
        content = response.text.strip()

        lines = content.strip().split("\n")
        has_configs = any(
            line.strip().startswith(("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"))
            for line in lines
        )
        if has_configs:
            return content

        try:
            decoded = ConfigParser.decode_base64(content)
            if decoded:
                decoded_lines = decoded.strip().split("\n")
                has_decoded = any(
                    line.strip().startswith(("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"))
                    for line in decoded_lines
                )
                if has_decoded:
                    return decoded
        except Exception:
            pass

        return content

    @staticmethod
    def get_iranian_date() -> str:
        now = jdatetime.date.today()
        return f"{now.year:04d}-{now.month:02d}-{now.day:02d}"

    @staticmethod
    def rename_configs(configs: List[V2RayConfig]) -> List[V2RayConfig]:
        date_str = SubscriptionManager.get_iranian_date()
        sorted_configs = sorted(configs, key=lambda c: c.latency_ms if c.latency_ms >= 0 else 99999)
        for i, config in enumerate(sorted_configs, 1):
            new_remark = f"@{CHANNEL_NAME} | {date_str} #{i}"
            if config.raw.startswith("vmess://"):
                config.raw = SubscriptionManager._update_vmess_remark(config.raw, new_remark)
            elif config.raw.startswith("vless://"):
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            elif config.raw.startswith("trojan://"):
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            elif config.raw.startswith("ss://"):
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            elif config.raw.startswith("hysteria2://") or config.raw.startswith("hy2://"):
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            elif config.raw.startswith("tuic://"):
                config.raw = SubscriptionManager._update_uri_remark(config.raw, new_remark)
            config.remark = new_remark
        return sorted_configs

    @staticmethod
    def _update_vmess_remark(raw: str, new_remark: str) -> str:
        try:
            b64 = raw.replace("vmess://", "")
            decoded = ConfigParser.decode_base64(b64)
            config = json.loads(decoded)
            config["ps"] = new_remark
            new_b64 = base64.b64encode(json.dumps(config).encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"
        except Exception:
            return raw

    @staticmethod
    def _update_uri_remark(raw: str, new_remark: str) -> str:
        try:
            encoded_remark = quote(new_remark, safe="")
            if "#" in raw:
                base = raw.rsplit("#", 1)[0]
            else:
                base = raw
            return f"{base}#{encoded_remark}"
        except Exception:
            return raw

    @staticmethod
    def generate_base64_subscription(configs: List[V2RayConfig]) -> str:
        lines = [c.raw for c in configs]
        content = "\n".join(lines)
        return base64.b64encode(content.encode("utf-8")).decode("utf-8")

    @staticmethod
    def save_subscription(configs: List[V2RayConfig], output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        b64 = SubscriptionManager.generate_base64_subscription(configs)
        output_path.write_text(b64, encoding="utf-8")
        print(f"[INFO] Saved {len(configs)} configs to {output_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SubV2ray - V2Ray Config Health Checker")
    parser.add_argument("--sub-url", required=True, help="Subscription URL(s), comma-separated for multiple")
    parser.add_argument("--ssh-host", required=True, help="SSH server IP")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--ssh-user", required=True, help="SSH username")
    parser.add_argument("--ssh-key", required=True, help="SSH private key path")
    parser.add_argument("--max-latency", type=int, default=4000, help="Max latency in ms")
    parser.add_argument("--output", default="sub.txt", help="Output file path")
    parser.add_argument("--test-file", default="http://speedtest.tele2.net/5MB.zip", help="Download test URL")
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
            print(f"[WARNING] Failed to fetch from {url}: {e}")

    configs = all_configs
    print(f"[INFO] Total unique configs: {len(configs)}")

    if not configs:
        print("[ERROR] No valid configs found", file=sys.stderr)
        sys.exit(1)

    checker = HealthChecker(
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        max_latency_ms=args.max_latency,
        test_file_url=args.test_file,
    )
    results = checker.check_configs(configs)
    healthy_configs = [r.config for r in results if r.healthy]

    if healthy_configs:
        renamed = SubscriptionManager.rename_configs(healthy_configs)
        date_str = SubscriptionManager.get_iranian_date()
        print(f"\n[RENAMED] Configs renamed to @{CHANNEL_NAME} | {date_str} #N (sorted by ping)")
        for c in renamed:
            print(f"  {c.remark} | {c.latency_ms:.0f}ms")

    output_path = Path(args.output)
    SubscriptionManager.save_subscription(healthy_configs, output_path)

    if not healthy_configs:
        print("[WARNING] No healthy configs found, saving empty subscription")
    else:
        print(f"[SUCCESS] {len(healthy_configs)} healthy configs saved")


if __name__ == "__main__":
    main()
