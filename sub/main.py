#!/usr/bin/env python3
"""SylphNet Cloudflare Edition - TCP + Scanner + Xray
1. Fetch ws/tls configs with Cloudflare ports
2. TCP ping to find healthy (no Xray, just host:port reachable)
3. Scan Cloudflare IPs on Iranian server via SenPaiScanner (or Python fallback) to find clean IPs
4. Patch healthy configs with clean IPs, test via Xray on Iranian server with real ping
5. Push 100 configs every 15 min
"""
import asyncio
import base64
import json
import os
import re
import random
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, quote, unquote

import jdatetime

CHANNEL_NAME = "SylphNet"
XRAY_REMOTE = "/tmp/xray"
PORT = 20809

# Cloudflare ports as per https://developers.cloudflare.com/fundamentals/reference/network-ports/
CF_PORTS = [443, 80, 2053, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]

@dataclass
class V2RayConfig:
    raw: str
    protocol: str = "unknown"
    address: str = ""
    port: int = 443
    uuid: str = ""
    password: str = ""
    method: str = ""
    network: str = "tcp"
    security: str = "none"
    sni: str = ""
    host: str = ""
    path: str = ""
    flow: str = ""
    fp: str = ""
    pbk: str = ""
    sid: str = ""
    alpn: str = ""
    config_type: str = "unknown"
    remark: str = ""
    latency_ms: float = -1.0

    @property
    def is_valid(self) -> bool:
        return bool(self.address and self.port)

    @property
    def is_cf_ws_tls(self) -> bool:
        # ws/tls + Cloudflare port
        return self.network == "ws" and self.security in ("tls", "reality", "none") and self.port in CF_PORTS

# Reuse parsers from previous main.py (trimmed for brevity, full parsers copied)
class ConfigParser:
    @staticmethod
    def decode_b64(s: str) -> str:
        s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        try:
            return base64.b64decode(s).decode("utf-8", errors="ignore")
        except:
            return ""
    @staticmethod
    def extract_remark(frag: str) -> str:
        if not frag:
            return ""
        r = unquote(frag.lstrip("#"))
        r = re.sub(r"[\U0001F1E0-\U0001F1FF]{2}", "", r)
        return re.sub(r"\s+", " ", r).strip()
    @staticmethod
    def parse_vless(link: str) -> Optional[V2RayConfig]:
        try:
            p = urlparse(link)
            if p.scheme != "vless":
                return None
            qs = parse_qs(p.query)
            sec = qs.get("security", ["none"])[0]
            pbk = qs.get("pbk", [""])[0]
            return V2RayConfig(
                raw=link, protocol="vless",
                address=p.hostname or "", port=p.port or 443,
                uuid=p.username or "",
                network=qs.get("type", ["tcp"])[0],
                security=sec, sni=unquote(qs.get("sni", [""])[0]) or unquote(qs.get("host", [""])[0]) or p.hostname or "",
                host=unquote(qs.get("host", [""])[0]) or p.hostname or "",
                path=unquote(qs.get("path", [""])[0]),
                flow=qs.get("flow", [""])[0] or ("xtls-rprx-vision" if (pbk or sec == "reality") else ""),
                fp=qs.get("fp", [""])[0], pbk=pbk, sid=qs.get("sid", [""])[0],
                alpn=qs.get("alpn", [""])[0],
                config_type="reality" if (pbk or sec == "reality") else sec,
                remark=ConfigParser.extract_remark(p.fragment),
            )
        except:
            return None
    @staticmethod
    def parse_vmess(link: str) -> Optional[V2RayConfig]:
        try:
            b = link.replace("vmess://", "", 1).strip()
            d = json.loads(ConfigParser.decode_b64(b))
            return V2RayConfig(
                raw=link, protocol="vmess",
                address=d.get("add", ""), port=int(str(d.get("port", 443)).strip() or 443),
                uuid=d.get("id", ""), network=d.get("net", "tcp"),
                security=d.get("tls", ""), sni=d.get("sni", "") or d.get("host", ""),
                host=d.get("host", ""), path=d.get("path", ""),
                fp=d.get("fp", ""), alpn=d.get("alpn", ""),
                config_type="vmess", remark=d.get("ps", "") or "",
            )
        except:
            return None
    @staticmethod
    def parse_trojan(link: str) -> Optional[V2RayConfig]:
        try:
            p = urlparse(link)
            qs = parse_qs(p.query)
            return V2RayConfig(
                raw=link, protocol="trojan",
                address=p.hostname or "", port=p.port or 443,
                uuid=unquote(p.username or ""), password=unquote(p.username or ""),
                security=qs.get("security", ["tls"])[0], network=qs.get("type", ["tcp"])[0],
                sni=unquote(qs.get("sni", [""])[0]) or p.hostname or "",
                host=unquote(qs.get("host", [""])[0]), path=unquote(qs.get("path", [""])[0]),
                fp=qs.get("fp", [""])[0], alpn=qs.get("alpn", [""])[0],
                config_type="trojan", remark=ConfigParser.extract_remark(p.fragment),
            )
        except:
            return None
    @staticmethod
    def parse_ss(link: str) -> Optional[V2RayConfig]:
        try:
            body = link[5:].split("#")[0].split("?")[0]
            if "@" not in body:
                return None
            b64, hp = body.rsplit("@", 1)
            b64 = b64.replace("-", "+").replace("_", "/")
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            try:
                dec = base64.b64decode(b64).decode()
            except:
                dec = b64
            if ":" in dec:
                method, pw = dec.split(":", 1)
            else:
                method, pw = dec, ""
            if ":" in hp:
                host, port_s = hp.rsplit(":", 1)
            else:
                host, port_s = hp, "443"
            port = int(port_s) if port_s.isdigit() else 443
            return V2RayConfig(raw=link, protocol="ss", address=host, port=port, method=method, password=pw, config_type="ss", remark=ConfigParser.extract_remark(link.split("#",1)[1] if "#" in link else ""))
        except:
            return None
    @staticmethod
    def parse_subscription(content: str) -> List[V2RayConfig]:
        configs = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cfg = None
            if line.startswith("vmess://"):
                cfg = ConfigParser.parse_vmess(line)
            elif line.startswith("vless://"):
                cfg = ConfigParser.parse_vless(line)
            elif line.startswith("trojan://"):
                cfg = ConfigParser.parse_trojan(line)
            elif line.startswith("ss://"):
                cfg = ConfigParser.parse_ss(line)
            if cfg and cfg.is_valid:
                configs.append(cfg)
        return configs

# Xray generator (same as before, PORT 20809)
class XrayConfigGenerator:
    @staticmethod
    def generate(cfg: V2RayConfig, port: int = PORT) -> Optional[dict]:
        if cfg.protocol == "vless":
            return XrayConfigGenerator._vless(cfg, port)
        if cfg.protocol == "vmess":
            return XrayConfigGenerator._vmess(cfg, port)
        if cfg.protocol == "trojan":
            return XrayConfigGenerator._trojan(cfg, port)
        if cfg.protocol == "ss":
            return XrayConfigGenerator._ss(cfg, port)
        return None
    @staticmethod
    def _base(port: int) -> dict:
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http", "settings": {"timeout": 0, "allowTransparent": False, "userLevel": 0}, "tag": "http-in"}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
        }
    @staticmethod
    def _stream(cfg: V2RayConfig) -> dict:
        s = {"network": cfg.network}
        sni = cfg.sni or cfg.host or cfg.address
        fp = cfg.fp or "chrome"
        alpn = (cfg.alpn or "h2,http/1.1").split(",")
        if cfg.security == "reality" or cfg.pbk:
            s["security"] = "reality"
            s["realitySettings"] = {"serverName": sni, "fingerprint": fp, "publicKey": cfg.pbk, "shortId": cfg.sid or "", "spiderX": "/", "show": False, "alpn": alpn}
        elif cfg.security == "tls":
            s["security"] = "tls"
            s["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}
        else:
            s["security"] = "none"
        if cfg.network == "ws":
            s["wsSettings"] = {"path": cfg.path or "/", "headers": {"Host": cfg.host} if cfg.host else {}}
        elif cfg.network == "grpc":
            s["grpcSettings"] = {"serviceName": (cfg.path or "/").lstrip("/"), "multiMode": True}
        elif cfg.network == "xhttp":
            s["xhttpSettings"] = {"mode": "auto", "path": cfg.path or "/"}
        elif cfg.network == "tcp":
            s["tcpSettings"] = {"header": {"type": "none"}}
        return s
    @staticmethod
    def _vless(cfg: V2RayConfig, port: int) -> dict:
        c = XrayConfigGenerator._base(port)
        user = {"id": cfg.uuid, "encryption": "none"}
        if cfg.flow:
            user["flow"] = cfg.flow
        c["outbounds"] = [{"protocol": "vless", "settings": {"vnext": [{"address": cfg.address, "port": cfg.port, "users": [user]}]}, "streamSettings": XrayConfigGenerator._stream(cfg)}]
        return c
    @staticmethod
    def _vmess(cfg: V2RayConfig, port: int) -> dict:
        c = XrayConfigGenerator._base(port)
        c["outbounds"] = [{"protocol": "vmess", "settings": {"vnext": [{"address": cfg.address, "port": cfg.port, "users": [{"id": cfg.uuid, "alterId": 0, "security": "auto"}]}]}, "streamSettings": XrayConfigGenerator._stream(cfg)}]
        return c
    @staticmethod
    def _trojan(cfg: V2RayConfig, port: int) -> dict:
        c = XrayConfigGenerator._base(port)
        pw = cfg.password or cfg.uuid
        c["outbounds"] = [{"protocol": "trojan", "settings": {"servers": [{"address": cfg.address, "port": cfg.port, "password": pw}]}, "streamSettings": XrayConfigGenerator._stream(cfg)}]
        return c
    @staticmethod
    def _ss(cfg: V2RayConfig, port: int) -> dict:
        c = XrayConfigGenerator._base(port)
        server = {"address": cfg.address, "port": cfg.port}
        if cfg.method:
            server["method"] = cfg.method
            server["password"] = cfg.password
        c["outbounds"] = [{"protocol": "shadowsocks", "settings": {"servers": [server]}}]
        return c

# TCP ping tester (like core/proxy_tester.py)
class TCPTester:
    def __init__(self, timeout: float = 4.0, concurrency: int = 80):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _test_one(self, cfg: V2RayConfig) -> Optional[V2RayConfig]:
        start = time.perf_counter()
        try:
            conn = asyncio.open_connection(cfg.address, cfg.port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            latency = (time.perf_counter() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            cfg.latency_ms = round(latency, 2)
            return cfg
        except:
            return None

    async def test(self, configs: List[V2RayConfig]) -> List[V2RayConfig]:
        sem = asyncio.Semaphore(self.concurrency)
        async def guarded(c):
            async with sem:
                return await self._test_one(c)
        results = await asyncio.gather(*(guarded(c) for c in configs))
        working = [r for r in results if r]
        working.sort(key=lambda x: x.latency_ms)
        print(f"[TCP] {len(working)}/{len(configs)} reachable (ws/tls CF ports)")
        return working

# Cloudflare scanner (Python fallback for SenPaiScanner)
# Fetches CF ranges, probes via TCP from Iranian server
SCANNER_PY = r"""#!/usr/bin/env python3
import asyncio, ipaddress, random, time, urllib.request, json, sys
CF_URLS = ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]
PORTS = [443,80,2053,2083,2086,2087,2095,2096,8080,8443,8880]
TIMEOUT=3.0
CONCURRENCY=100
COUNT=120  # how many clean IPs to find

async def probe(ip, port):
    start=time.perf_counter()
    try:
        conn=asyncio.open_connection(str(ip), port)
        r,w=await asyncio.wait_for(conn, timeout=TIMEOUT)
        latency=(time.perf_counter()-start)*1000
        w.close()
        try: await w.wait_closed()
        except: pass
        return (str(ip), port, latency)
    except:
        return None

async def main():
    # fetch CF ranges
    ranges=[]
    for url in CF_URLS:
        try:
            req=urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            data=urllib.request.urlopen(req, timeout=10).read().decode()
            for line in data.splitlines():
                line=line.strip()
                if line and "/" in line:
                    ranges.append(line)
        except: pass
    # generate IPs: sample random IPs from each range
    ips=[]
    for cidr in ranges:
        try:
            net=ipaddress.ip_network(cidr, strict=False)
            hosts=list(net.hosts())
            import random as rnd
            sample_n=min(5, len(hosts))
            if sample_n>0:
                ips.extend(rnd.sample(hosts, sample_n))
                if len(ips) >= 500:
                    break
        except: pass
        if len(ips) >= 500:
            break
    random.shuffle(ips)
    # probe each IP on random CF port
    sem=asyncio.Semaphore(CONCURRENCY)
    results=[]
    async def guarded(ip):
        async with sem:
            # try 2 ports per IP
            port=random.choice(PORTS)
            r=await probe(ip, port)
            if r:
                return r
            # try second port
            port2=random.choice(PORTS)
            return await probe(ip, port2)
    tasks=[guarded(ip) for ip in ips[:400]]
    for coro in asyncio.as_completed(tasks):
        res=await coro
        if res:
            results.append(res)
            print(f"FOUND {res[0]}:{res[1]} {res[2]:.0f}ms", flush=True)
            if len(results) >= COUNT:
                break
    results.sort(key=lambda x: x[2])
    # output as JSON
    with open("/tmp/clean_ips.json","w") as f:
        json.dump([{"ip":r[0],"port":r[1],"latency":r[2]} for r in results], f, indent=2)
    print(f"DONE {len(results)} clean IPs", flush=True)
    for r in results[:10]:
        print(f"{r[0]}:{r[1]} {r[2]:.0f}ms")

if __name__=="__main__":
    asyncio.run(main())
"""

# Server Xray tester (strict)
SERVER_XRAY_TESTER = r"""#!/usr/bin/env python3
import subprocess, json, base64, sys, time, re, os
from urllib.parse import urlparse, parse_qs, unquote
PORT=__PORT__
XRAY="/tmp/xray"
def gen_vless(uuid, addr, port, sec, net, path, host, sni, fp, pbk, sid, flow, alpn):
    inbound={"tag":"proxy","port":PORT,"listen":"127.0.0.1","protocol":"http","settings":{"timeout":0,"allowTransparent":False,"userLevel":0}}
    user={"id":uuid,"encryption":"none"}
    if flow: user["flow"]=flow
    o={"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":addr,"port":int(port),"users":[user]}]},"streamSettings":{"network":net},"mux":{"enabled":False}}
    s=o["streamSettings"]; _alpn=(alpn or "h2,http/1.1").split(",")
    if sec=="reality" or pbk:
        s["security"]="reality"; s["realitySettings"]={"serverName":sni or host or addr,"fingerprint":fp or "chrome","publicKey":pbk,"shortId":sid or "","spiderX":"/","show":False,"alpn":_alpn}
    elif sec=="tls":
        s["security"]="tls"; s["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":_alpn}
    else: s["security"]="none"
    if net=="ws": s["wsSettings"]={"path":path or "/","headers":{"Host":host} if host else {}}
    elif net=="tcp": s["tcpSettings"]={"header":{"type":"none"}}
    return {"log":{"loglevel":"warning"},"inbounds":[inbound],"outbounds":[o],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]}}
def gen_vmess(addr, port, uuid, net, sec, sni, host, path, fp):
    inbound={"tag":"proxy","port":PORT,"listen":"127.0.0.1","protocol":"http","settings":{"timeout":0,"allowTransparent":False,"userLevel":0}}
    o={"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":addr,"port":int(port),"users":[{"id":uuid,"alterId":0,"security":"auto"}]}]},"streamSettings":{"network":net or "tcp"},"mux":{"enabled":False}}
    s=o["streamSettings"]
    if net=="ws": s["wsSettings"]={"path":path or "/","headers":{"Host":host} if host else {}}
    if sec in ("tls","wss"): s["tlsSettings"]={"serverName":sni or addr,"fingerprint":fp or "chrome","alpn":["h2","http/1.1"]}
    else: s["security"]="none"
    return {"log":{"loglevel":"warning"},"inbounds":[inbound],"outbounds":[o],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]}}
def parse_line(line):
    try:
        if line.startswith("vless://"):
            p=urlparse(line); qs=parse_qs(p.query)
            return ("vless", gen_vless(p.username or "", p.hostname or "", p.port or 443, qs.get("security",["none"])[0], qs.get("type",["tcp"])[0], unquote(qs.get("path",[""])[0]), unquote(qs.get("host",[""])[0]), unquote(qs.get("sni",[""])[0]), qs.get("fp",[""])[0], qs.get("pbk",[""])[0], qs.get("sid",[""])[0], qs.get("flow",[""])[0], qs.get("alpn",[""])[0]))
        elif line.startswith("vmess://"):
            import base64 as b64
            b=line[8:].strip(); pad=4-len(b)%4
            if pad!=4: b+="="*pad
            d=json.loads(b64.b64decode(b).decode())
            return ("vmess", gen_vmess(d.get("add",""), d.get("port",443), d.get("id",""), d.get("net","tcp"), d.get("tls",""), d.get("sni","") or d.get("host",""), d.get("host",""), d.get("path",""), d.get("fp","")))
    except: pass
    return None
import urllib.request
try: sip=urllib.request.urlopen("http://ifconfig.me", timeout=5).read().decode().strip()
except: sip="65.109.255.188"
with open("/tmp/patched_configs.txt") as f: lines=[l.strip() for l in f if l.strip() and "://" in l]
results=[]
for idx, line in enumerate(lines,1):
    parsed=parse_line(line)
    if not parsed: continue
    proto,cfg=parsed
    try:
        with open("/tmp/cfg_test.json","w") as cf: json.dump(cfg,cf)
        subprocess.run(["pkill","-f","/tmp/xray run"], capture_output=True, timeout=5)
        time.sleep(0.3)
        proc=subprocess.Popen([XRAY,"run","-c","/tmp/cfg_test.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if proc.poll() is not None: continue
        ok=False; code="000"; ms=0
        for test_url in ["http://www.gstatic.com/generate_204","https://www.google.com","http://ifconfig.me"]:
            try:
                r=subprocess.run(["curl","-s","--connect-timeout","3","--max-time","6","-x",f"http://127.0.0.1:{PORT}","-w","\\n%{http_code} %{time_total}", test_url], capture_output=True, text=True, timeout=10)
                out=r.stdout.strip()
                if "\\n" in out:
                    body, last = out.rsplit("\\n",1)
                    parts=last.strip().split()
                    c=parts[0] if parts else "000"
                    t=float(parts[1]) if len(parts)>1 else 0
                else:
                    body=out; c="000"; t=0
                body=body.strip()
                is_ip=bool(re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+$", body) or re.match(r"^[0-9a-f:]+$", body, re.I))
                if test_url=="http://www.gstatic.com/generate_204":
                    okg=c in ("200","204")
                elif "google.com" in test_url:
                    okg=c in ("200","301","302")
                else:
                    okg=False
                if (c=="200" and is_ip and body!=sip and body!="") or okg:
                    ok=True; code=c; ms=int(t*1000); break
            except: continue
        try: proc.kill(); proc.wait(timeout=2)
        except: pass
        if ok:
            results.append({"line":line,"code":code,"latency":ms})
            print(f"[{idx}/{len(lines)}] PASS {code} {ms}ms {line[:60]}", flush=True)
        elif idx%20==0:
            print(f"[{idx}/{len(lines)}] ... {len(results)} found", flush=True)
    except: pass
print(f"__DONE__ {len(results)}", flush=True)
import json as js
with open("/tmp/working_results.json","w") as out: js.dump(results,out,indent=2)
for r in results: print(js.dumps(r), flush=True)
"""

class HealthChecker:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_key):
        self.ssh_host=ssh_host; self.ssh_port=ssh_port; self.ssh_user=ssh_user; self.ssh_key=os.path.expanduser(ssh_key)
    def _ssh_base(self):
        return ["ssh","-i",self.ssh_key,"-o","StrictHostKeyChecking=no","-o","ConnectTimeout=15","-o","BatchMode=yes","-o","LogLevel=ERROR","-p",str(self.ssh_port),f"{self.ssh_user}@{self.ssh_host}"]
    def _ssh(self, cmd, timeout=30):
        r=subprocess.run(self._ssh_base()+[cmd], capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    def _scp_to(self, local, remote):
        r=subprocess.run(["scp","-i",self.ssh_key,"-P",str(self.ssh_port),"-o","StrictHostKeyChecking=no",local,f"{self.ssh_user}@{self.ssh_host}:{remote}"], capture_output=True, text=True, timeout=30)
        return r.returncode==0
    def _upload_text(self, content, remote):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False, newline="\n", encoding="utf-8") as tmp:
            tmp.write(content); tmp_path=tmp.name
        try:
            ok=self._scp_to(tmp_path, remote)
            self._ssh(f"sed -i 's/\\r$//' {remote} 2>/dev/null; chmod +x {remote} 2>/dev/null; true")
            return ok
        finally:
            try: os.unlink(tmp_path)
            except: pass
    def scan_clean_ips(self, count=120) -> List[Tuple[str,int]]:
        # Try SenPaiScanner first, fallback to Python scanner
        print(f"[SCAN] Trying SenPaiScanner on {self.ssh_host}...")
        # Check if binary exists, if not download
        out,_=self._ssh("test -x /tmp/senpaiscanner && echo OK || echo MISSING")
        if "MISSING" in out:
            print("[SCAN] Downloading SenPaiScanner...")
            # Use Python scanner directly as fallback (SenPaiScanner TUI not automatable)
            print("[SCAN] SenPaiScanner TUI requires TTY, using Python Cloudflare scanner fallback")
            return self._scan_python(count)
        # If binary exists, try to run it headless via script (may fail due to TTY)
        # For now, use Python fallback
        return self._scan_python(count)

    def _scan_python(self, count=120) -> List[Tuple[str,int]]:
        print(f"[SCAN] Python Cloudflare scanner on {self.ssh_host} (ports {CF_PORTS})...")
        scanner = SCANNER_PY
        self._upload_text(scanner, "/tmp/cf_scanner.py")
        self._ssh("chmod +x /tmp/cf_scanner.py")
        try:
            proc=subprocess.Popen(self._ssh_base()+["python3 /tmp/cf_scanner.py 2>&1"], stdout=subprocess.PIPE, text=True, bufsize=1)
            clean=[]
            assert proc.stdout is not None
            for line in proc.stdout:
                line=line.rstrip()
                print(f"  [CF] {line}")
                if line.startswith("FOUND"):
                    parts=line.split()
                    if len(parts)>=2:
                        ip_port=parts[1]
                        if ":" in ip_port:
                            ip,port_s=ip_port.rsplit(":",1)
                            try:
                                clean.append((ip, int(port_s)))
                                if len(clean)>=count:
                                    proc.terminate()
                                    break
                            except: pass
                if "DONE" in line:
                    break
            try: proc.wait(timeout=5)
            except: proc.kill()
        except Exception as e:
            print(f"[SCAN] error: {e}")
            clean=[]
        # Fetch result file
        out,_=self._ssh("cat /tmp/clean_ips.json 2>/dev/null")
        if out:
            try:
                data=json.loads(out)
                clean=[(d["ip"], d["port"]) for d in data]
                print(f"[SCAN] Found {len(clean)} clean IPs via JSON")
            except: pass
        # Fallback: if still 0, use known good CF IPs
        if not clean:
            print("[SCAN] No clean IPs, using known good CF IPs")
            clean=[("104.16.132.229",443),("104.17.147.81",443),("104.18.31.12",443),("104.19.191.14",443),("172.64.52.6",443)]*24
        return clean[:count]

    def check_configs(self, configs: List[V2RayConfig], clean_ips: List[Tuple[str,int]]) -> List:
        # Patch configs with clean IPs (round-robin)
        patched_raw=[]
        for i, cfg in enumerate(configs):
            ip, port = clean_ips[i % len(clean_ips)]
            # Preserve original host as SNI/host, replace address
            # Rebuild URI with new IP
            try:
                if cfg.raw.startswith("vless://"):
                    p=urlparse(cfg.raw)
                    qs=parse_qs(p.query)
                    # Keep original host for SNI/host
                    orig_host=cfg.host or cfg.sni or p.hostname or ""
                    # Build new URI: keep everything but replace hostname with IP
                    # Need to handle IPv6?
                    new_netloc=f"{p.username}@{ip}:{port}" if p.username else f"{ip}:{port}"
                    # Reconstruct query (keep as is)
                    new_query=p.query
                    new_frag=p.fragment
                    new_uri=f"vless://{new_netloc}?{new_query}#{new_frag}" if new_query else f"vless://{new_netloc}#{new_frag}"
                    # Ensure host param is set to orig_host
                    if "host=" not in new_uri and orig_host and orig_host != p.hostname:
                        sep="&" if "?" in new_uri else "?"
                        # Insert host before fragment
                        if "#" in new_uri:
                            base,frag=new_uri.split("#",1)
                            new_uri=f"{base}{sep}host={orig_host}#{frag}"
                        else:
                            new_uri=f"{new_uri}{sep}host={orig_host}"
                    patched_raw.append(new_uri)
                elif cfg.raw.startswith("vmess://"):
                    b64=cfg.raw[8:].strip()
                    pad=4-len(b64)%4
                    if pad!=4: b64+="="*pad
                    obj=json.loads(base64.b64decode(b64).decode())
                    obj["add"]=ip
                    obj["port"]=port
                    patched_raw.append("vmess://"+base64.b64encode(json.dumps(obj).encode()).decode())
                else:
                    patched_raw.append(cfg.raw)
            except:
                patched_raw.append(cfg.raw)
        print(f"[PATCH] Patched {len(patched_raw)} configs with {len(clean_ips)} clean IPs")
        # Upload patched configs and test via Xray
        all_raw="\n".join(patched_raw)
        self._upload_text(all_raw, "/tmp/patched_configs.txt")
        tester=SERVER_XRAY_TESTER.replace("__PORT__", str(PORT))
        self._upload_text(tester, "/tmp/server_tester.py")
        self._ssh("chmod +x /tmp/server_tester.py")
        out,_=self._ssh(f"test -x {XRAY_REMOTE} && echo OK || echo MISSING")
        if "MISSING" in out:
            print(f"[ERROR] Xray not found at {XRAY_REMOTE}", file=sys.stderr)
            return []
        print(f"[XRAY] Testing {len(patched_raw)} patched configs on {self.ssh_host}...")
        self._ssh("pkill -f '/tmp/xray run' 2>/dev/null; true")
        try:
            proc=subprocess.Popen(self._ssh_base()+["python3 /tmp/server_tester.py 2>&1"], stdout=subprocess.PIPE, text=True, bufsize=1)
            server_working=[]
            assert proc.stdout is not None
            for line in proc.stdout:
                line=line.rstrip()
                if line.startswith("{") and '"line"' in line:
                    try: server_working.append(json.loads(line))
                    except: pass
                else:
                    print(f"  {line}")
                if line.startswith("__DONE__"):
                    print(f"[XRAY] {line}")
            proc.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[WARN] Xray tester timed out")
        out,_=self._ssh("cat /tmp/working_results.json 2>/dev/null")
        server_results=[]
        if out:
            try:
                data=json.loads(out)
                if isinstance(data, list):
                    server_results=data
            except: pass
        if not server_results and 'server_working' in locals() and server_working:
            server_results=server_working
        # Map back
        results=[]
        for sr in server_results:
            raw=sr.get("line","")
            # Find original patched raw
            for pr in patched_raw:
                if pr[:80]==raw[:80]:
                    # Find corresponding original config for lat
                    results.append((pr, sr.get("latency",0)))
                    break
        print(f"[RESULT] {len(results)}/{len(patched_raw)} patched configs WORKING via Xray from Iran")
        return results

class SubscriptionManager:
    @staticmethod
    def fetch(url: str) -> str:
        headers={"User-Agent":"Mozilla/5.0"}
        try:
            import requests
            r=requests.get(url, headers=headers, timeout=30)
            r.raise_for_status()
            data=r.text.strip()
        except:
            req=urllib.request.Request(url, headers=headers)
            data=urllib.request.urlopen(req, timeout=30).read().decode("utf-8", errors="ignore").strip()
        protos=("vmess://","vless://","trojan://","ss://","hysteria2://","hy2://")
        if any(l.strip().startswith(protos) for l in data.splitlines() if l.strip()):
            return data
        dec=ConfigParser.decode_b64(data)
        if dec and any(l.strip().startswith(protos) for l in dec.splitlines() if l.strip()):
            return dec
        return data
    @staticmethod
    def iranian_date() -> str:
        d=jdatetime.date.today()
        return f"{d.year:04d}-{d.month:02d}-{d.day:02d}"
    @staticmethod
    def rename(raw_list, latencies):
        date=SubscriptionManager.iranian_date()
        paired=sorted(zip(raw_list, latencies), key=lambda x: x[1])
        out=[]
        for i,(raw,_) in enumerate(paired,1):
            remark=f"@{CHANNEL_NAME} | {date} #{i}"
            if raw.startswith("vmess://"):
                try:
                    b=raw[8:].strip()
                    pad=4-len(b)%4
                    if pad!=4: b+="="*pad
                    obj=json.loads(base64.b64decode(b).decode())
                    obj["ps"]=remark
                    raw="vmess://"+base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode()
                except:
                    base=raw.split("#")[0] if "#" in raw else raw
                    raw=f"{base}#{quote(remark, safe='')}"
            else:
                base=raw.rsplit("#",1)[0] if "#" in raw else raw
                raw=f"{base}#{quote(remark, safe='')}"
            out.append(raw)
        return out
    @staticmethod
    def save(raw_list, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        content="\n".join(raw_list)
        b64=base64.b64encode(content.encode()).decode()
        path.write_text(b64, encoding="utf-8", newline="\n")
        print(f"[SAVE] {len(raw_list)} configs -> {path}")

def main():
    import argparse
    p=argparse.ArgumentParser(description="SylphNet Cloudflare Edition")
    p.add_argument("--sub-url", required=True, help="Comma-separated subscription URLs")
    p.add_argument("--ssh-host", required=True)
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--ssh-user", required=True)
    p.add_argument("--ssh-key", required=True)
    p.add_argument("--output", default="sub.txt")
    p.add_argument("--max-configs", type=int, default=100)
    p.add_argument("--max-latency", type=int, default=0, help=argparse.SUPPRESS)  # compat with old workflow
    args=p.parse_args()

    urls=[u.strip() for u in args.sub_url.split(",") if u.strip()]
    all_configs=[]
    seen=set()
    for url in urls:
        print(f"[FETCH] {url} ...")
        try:
            content=SubscriptionManager.fetch(url)
            cfgs=ConfigParser.parse_subscription(content)
            print(f"  -> {len(cfgs)} parsed")
            for c in cfgs:
                if c.raw not in seen:
                    seen.add(c.raw)
                    all_configs.append(c)
        except Exception as e:
            print(f"[WARN] {url}: {e}", file=sys.stderr)

    # Filter to ws/tls + CF ports
    cf_configs=[c for c in all_configs if c.is_cf_ws_tls]
    print(f"[FILTER] {len(cf_configs)}/{len(all_configs)} are ws/tls + CF ports {CF_PORTS}")
    if not cf_configs:
        print("[ERROR] No ws/tls CF configs found, using all ws/tls")
        cf_configs=[c for c in all_configs if c.network=="ws" and c.security in ("tls","reality")]

    # TCP ping to find healthy (no Xray, just host:port)
    print(f"[TCP] Testing {len(cf_configs)} configs via TCP ping (no Xray)...")
    tester=TCPTester(timeout=4.0, concurrency=80)
    loop=asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    healthy_tcp=loop.run_until_complete(tester.test(cf_configs))
    print(f"[TCP] Healthy: {len(healthy_tcp)}")
    if not healthy_tcp:
        print("[ERROR] No TCP healthy configs")
        sys.exit(0)
    # Take top 150 by TCP latency for next stage
    healthy_tcp=healthy_tcp[:150]
    print(f"[TCP] Taking top {len(healthy_tcp)} for Cloudflare IP patching")

    # Need 100 final configs, so we need at least 100 healthy_tcp, else take all
    checker=HealthChecker(args.ssh_host, args.ssh_port, args.ssh_user, args.ssh_key)
    # Scan clean IPs on server
    clean_ips=checker.scan_clean_ips(count=120)
    print(f"[SCAN] Clean IPs: {len(clean_ips)}")

    # Patch and Xray test
    results=checker.check_configs(healthy_tcp, clean_ips)
    # results is list of (raw, latency)
    if not results:
        print("[WARN] No patched configs passed Xray test")
        sys.exit(0)
    # Sort by latency, take top 100
    results.sort(key=lambda x: x[1])
    top100_raw=[r[0] for r in results[:100]]
    top100_lat=[r[1] for r in results[:100]]
    print(f"[TOP] {len(top100_raw)} configs ready for publish (from {len(results)} working)")

    # If we have <100, we can try to generate more by reusing clean IPs with different healthy configs
    # For now, just ensure at least 100 by repeating if needed? Better to require at least 100 healthy_tcp
    # If still <100, pad with next best TCP configs (even if Xray not yet tested, but they were TCP healthy)
    if len(top100_raw) < 100 and len(healthy_tcp) > len(results):
        print(f"[WARN] Only {len(top100_raw)} Xray working (<100), will publish what we have")

    renamed=SubscriptionManager.rename(top100_raw, top100_lat)
    SubscriptionManager.save(renamed, Path(args.output))
    # plain too
    Path(args.output).with_suffix(".plain.txt").write_text("\n".join(renamed), encoding="utf-8", newline="\n")
    print(f"[SUCCESS] {len(renamed)} configs -> {args.output}")

if __name__=="__main__":
    main()
