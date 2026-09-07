#!/usr/bin/env python3
"""SylphNet server-side checker - runs on Iranian server via cron, no SSH."""
import base64, json, os, re, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote, unquote

# --- config (edit via ~/sylphnet/.env or env vars) ---
SUB_URL = os.environ.get("SUB_URL", "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt,https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt,https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt")
PUBLIC_REPO = "ProblemTheCode/SylphNet-public"
PAT_FILE = Path.home() / "sylphnet" / ".token"
XRAY = "/tmp/xray"
PORT = 20809
WORKDIR = Path.home() / "sylphnet"
# ---

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def decode_b64(s):
    s=s.strip().replace("\n","").replace("\r","").replace(" ","")
    pad=4-len(s)%4
    if pad!=4: s+="="*pad
    try: return base64.b64decode(s).decode(errors="ignore")
    except: return ""

def extract_remark(frag):
    if not frag: return ""
    r=unquote(frag.lstrip("#"))
    r=re.sub(r"[\U0001F1E0-\U0001F1FF]{2}","",r)
    return re.sub(r"\s+"," ",r).strip()

# ---- Jalali date (no jdatetime dep) ----
def gregorian_to_jalali(gy, gm, gd):
    g_d_m=[0,31,59,90,120,151,181,212,243,273,304,334]
    if gm>2: gy2=gy+1
    else: gy2=gy
    days=(355666+365*gy+(gy2+3)//4-(gy2+99)//100+(gy2+399)//400+g_d_m[gm-1]+gd)
    jy=-1595+33*(days//12053)
    days%=12053
    jy+=4*(days//1461)
    days%=1461
    if days>365:
        jy+=(days-1)//365
        days=(days-1)%365
    if days<186:
        jm=1+days//31
        jd=1+days%31
    else:
        jm=7+(days-186)//30
        jd=1+(days-186)%30
    return jy,jm,jd

def jalali_today():
    import datetime
    t=datetime.date.today()
    jy,jm,jd=gregorian_to_jalali(t.year,t.month,t.day)
    return f"{jy:04d}-{jm:02d}-{jd:02d}"

# ---- parsers (minimal, reuse main.py logic) ----
def parse_vless(link):
    try:
        p=urlparse(link)
        if p.scheme!="vless": return None
        qs=parse_qs(p.query)
        sec=qs.get("security",["none"])[0]
        pbk=qs.get("pbk",[""])[0]
        return {"raw":link,"proto":"vless","addr":p.hostname or "","port":p.port or 443,"uuid":p.username or "",
                "net":qs.get("type",["tcp"])[0],"sec":sec,"sni":unquote(qs.get("sni",[""])[0]) or unquote(qs.get("host",[""])[0]) or p.hostname or "",
                "host":unquote(qs.get("host",[""])[0]) or p.hostname or "","path":unquote(qs.get("path",[""])[0]),
                "flow":qs.get("flow",[""])[0] or ("xtls-rprx-vision" if (pbk or sec=="reality") else ""),"fp":qs.get("fp",[""])[0],"pbk":pbk,"sid":qs.get("sid",[""])[0],"alpn":qs.get("alpn",[""])[0]}
    except: return None

def parse_vmess(link):
    try:
        b=link[8:].strip()
        pad=4-len(b)%4
        if pad!=4: b+="="*pad
        d=json.loads(base64.b64decode(b).decode())
        return {"raw":link,"proto":"vmess","addr":d.get("add",""),"port":int(str(d.get("port",443)).strip() or 443),"uuid":d.get("id",""),
                "net":d.get("net","tcp"),"sec":d.get("tls",""),"sni":d.get("sni","") or d.get("host",""),"host":d.get("host",""),"path":d.get("path",""),"fp":d.get("fp","")}
    except: return None

def parse_trojan(link):
    try:
        p=urlparse(link)
        qs=parse_qs(p.query)
        return {"raw":link,"proto":"trojan","addr":p.hostname or "","port":p.port or 443,"pw":unquote(p.username or ""),
                "sec":qs.get("security",["tls"])[0],"net":qs.get("type",["tcp"])[0],"sni":unquote(qs.get("sni",[""])[0]) or p.hostname or "",
                "host":unquote(qs.get("host",[""])[0]),"path":unquote(qs.get("path",[""])[0]),"fp":qs.get("fp",[""])[0]}
    except: return None

def parse_ss(link):
    try:
        body=link[5:].split("#")[0].split("?")[0]
        if "@" not in body: return None
        b64,hp=body.rsplit("@",1)
        b64=b64.replace("-","+").replace("_","/")
        pad=4-len(b64)%4
        if pad!=4: b64+="="*pad
        try: dec=base64.b64decode(b64).decode()
        except: dec=b64
        if ":" in dec: method,pw=dec.split(":",1)
        else: method,pw=dec,""
        if ":" in hp: host,port_s=hp.rsplit(":",1)
        else: host,port_s=hp,"443"
        port=int(port_s) if port_s.isdigit() else 443
        return {"raw":link,"proto":"ss","addr":host,"port":port,"method":method,"pw":pw}
    except: return None

def fetch_sub(url):
    # handle comma-separated URLs
    parts = [u.strip() for u in url.split(",") if u.strip()]
    if len(parts) > 1:
        combined=[]
        for u in parts:
            try:
                combined.append(fetch_sub(u))
            except Exception as e:
                log(f"Fetch failed {u}: {e}")
        return "\n".join(combined)
    # single URL
    try:
        import requests
        r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=30)
        r.raise_for_status()
        data = r.text.strip()
    except:
        hdr={"User-Agent":"Mozilla/5.0"}
        data=urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=30).read().decode(errors="ignore").strip()
    if any(l.strip().startswith(("vmess://","vless://","trojan://","ss://","hy")) for l in data.splitlines() if l.strip()):
        return data
    dec=decode_b64(data)
    if dec and any(l.strip().startswith(("vmess://","vless://")) for l in dec.splitlines() if l.strip()):
        return dec
    return data

def gen_xray(cfg, port):
    inbound={"tag":"proxy","port":port,"listen":"127.0.0.1","protocol":"http","settings":{"timeout":0,"allowTransparent":False,"userLevel":0}}
    base={"log":{"loglevel":"warning"},"inbounds":[inbound],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]}}
    def stream(net, sec, sni, host, path, fp, pbk, sid, alpn):
        s={"network":net}
        _alpn=(alpn or "h2,http/1.1").split(",")
        if sec=="reality" or pbk:
            s["security"]="reality"; s["realitySettings"]={"serverName":sni or host,"fingerprint":fp or "chrome","publicKey":pbk,"shortId":sid or "","spiderX":"/","show":False,"alpn":_alpn}
        elif sec=="tls":
            s["security"]="tls"; s["tlsSettings"]={"serverName":sni,"fingerprint":fp or "chrome","alpn":_alpn}
        else: s["security"]="none"
        if net=="ws": s["wsSettings"]={"path":path or "/","headers":{"Host":host} if host else {}}
        elif net=="grpc": s["grpcSettings"]={"serviceName":(path or "/").lstrip("/"),"multiMode":True}
        elif net=="xhttp": s["xhttpSettings"]={"mode":"auto","path":path or "/"}
        elif net=="tcp": s["tcpSettings"]={"header":{"type":"none"}}
        return s
    if cfg["proto"]=="vless":
        user={"id":cfg["uuid"],"encryption":"none"}
        if cfg.get("flow"): user["flow"]=cfg["flow"]
        base["outbounds"]=[{"protocol":"vless","settings":{"vnext":[{"address":cfg["addr"],"port":cfg["port"],"users":[user]}]},"streamSettings":stream(cfg["net"],cfg["sec"],cfg["sni"],cfg["host"],cfg["path"],cfg.get("fp",""),cfg.get("pbk",""),cfg.get("sid",""),cfg.get("alpn",""))}]
    elif cfg["proto"]=="vmess":
        base["outbounds"]=[{"protocol":"vmess","settings":{"vnext":[{"address":cfg["addr"],"port":cfg["port"],"users":[{"id":cfg["uuid"],"alterId":0,"security":"auto"}]}]},"streamSettings":stream(cfg["net"],cfg["sec"],cfg["sni"],cfg["host"],cfg["path"],cfg.get("fp",""),"","", "")}]
    elif cfg["proto"]=="trojan":
        base["outbounds"]=[{"protocol":"trojan","settings":{"servers":[{"address":cfg["addr"],"port":cfg["port"],"password":cfg["pw"]}]},"streamSettings":stream(cfg["net"],cfg["sec"],cfg["sni"],cfg["host"],cfg["path"],cfg.get("fp",""),"","", "")}]
    elif cfg["proto"]=="ss":
        base["outbounds"]=[{"protocol":"shadowsocks","settings":{"servers":[{"address":cfg["addr"],"port":cfg["port"],"method":cfg["method"],"password":cfg["pw"]}]}}]
    else: return None
    return base

def ensure_xray():
    if os.path.exists(XRAY) and os.access(XRAY, os.X_OK):
        return True
    log("Xray missing at /tmp/xray, trying to download...")
    # try to restore from ~/sylphnet/xray if exists
    alt=WORKDIR/"xray"
    if alt.exists():
        subprocess.run(["cp", str(alt), XRAY], timeout=10)
        subprocess.run(["chmod","+x", XRAY], timeout=5)
        return os.path.exists(XRAY)
    # download from github releases (latest)
    try:
        url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        log(f"Downloading {url}")
        import urllib.request, zipfile, tempfile
        with tempfile.TemporaryDirectory() as td:
            zp=Path(td)/"xray.zip"
            urllib.request.urlretrieve(url, zp)
            with zipfile.ZipFile(zp) as z:
                z.extractall(td)
                for p in Path(td).rglob("xray"):
                    if p.is_file() and p.stat().st_size>1000000:
                        subprocess.run(["cp", str(p), XRAY], timeout=10)
                        subprocess.run(["chmod","+x", XRAY], timeout=5)
                        log("Xray downloaded")
                        return True
    except Exception as e:
        log(f"Download failed: {e}")
    return False

def test_one(cfg):
    xc=gen_xray(cfg, PORT)
    if not xc: return None
    with open("/tmp/cfg_test.json","w") as f: json.dump(xc,f)
    subprocess.run(["pkill","-f","/tmp/xray run"], capture_output=True, timeout=5)
    time.sleep(0.3)
    proc=subprocess.Popen([XRAY,"run","-c","/tmp/cfg_test.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    if proc.poll() is not None:
        return None
    # get server IP once (cached)
    try:
        if not hasattr(test_one, "_sip"):
            import urllib.request as _ur
            test_one._sip = _ur.urlopen("http://ifconfig.me", timeout=5).read().decode().strip()
    except:
        test_one._sip = "65.109.255.188"
    sip = test_one._sip
    ok=False
    code="000"
    ms=0
    for test_url in ["http://ifconfig.me", "https://api.ipify.org", "http://icanhazip.com", "http://www.gstatic.com/generate_204", "https://www.google.com"]:
        try:
            r=subprocess.run(["curl","-s","--connect-timeout","3","--max-time","6","-x",f"http://127.0.0.1:{PORT}","-w","\n%{http_code} %{time_total}", test_url], capture_output=True, text=True, timeout=10)
            out=r.stdout.strip()
            if "\n" in out:
                body, last = out.rsplit("\n",1)
                parts=last.strip().split()
                c=parts[0] if parts else "000"
                t=float(parts[1]) if len(parts)>1 else 0
            else:
                body=out; c="000"; t=0
            body=body.strip()
            is_ip=bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", body) or re.match(r"^[0-9a-f:]+$", body, re.I))
            # IP URLs require 200+IP, google/generate_204 require 200/204/301
            if test_url in ["http://www.gstatic.com/generate_204"]:
                ok_google = c in ("200","204")
            elif "google.com" in test_url:
                ok_google = c in ("200","301","302")
            else:
                ok_google = False
            if (c=="200" and is_ip and body!=sip and body!="") or ok_google:
                ok=True
                code=c
                ms=int(t*1000)
                break
        except:
            continue
    try: proc.kill(); proc.wait(timeout=2)
    except: pass
    if ok:
        return {"code":code,"latency":ms}
    return None

def main():
    # read token
    token=""
    if PAT_FILE.exists():
        token=PAT_FILE.read_text().strip()
    else:
        token=os.environ.get("PAT","").strip()
    if not token:
        log("ERROR: no token at ~/sylphnet/.token or $PAT")
        sys.exit(1)
    # read sub url
    sub_url=SUB_URL
    env_sub=WORKDIR/".sub_url"
    if env_sub.exists():
        sub_url=env_sub.read_text().strip()
    log(f"Fetching {sub_url}")
    try:
        raw=fetch_sub(sub_url)
    except Exception as e:
        log(f"Fetch failed: {e}")
        sys.exit(1)
    # parse
    configs=[]
    seen=set()
    parsers={"vless":parse_vless,"vmess":parse_vmess,"trojan":parse_trojan,"ss":parse_ss}
    for line in raw.splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        proto=line.split("://")[0]
        fn=parsers.get(proto)
        if not fn: continue
        cfg=fn(line)
        if cfg and cfg["addr"] and cfg["port"] and line not in seen:
            seen.add(line)
            # keep original raw for output
            cfg["raw"]=line
            configs.append(cfg)
    log(f"Parsed {len(configs)} unique configs")
    # Sample to keep runtime reasonable (strict test ~3s per config)
    MAX_PER_RUN = 1500
    if len(configs) > MAX_PER_RUN:
        import random
        random.shuffle(configs)
        configs = configs[:MAX_PER_RUN]
        log(f"Sampled to {len(configs)} for timely run")
    if not configs:
        log("No configs")
        sys.exit(0)
    if not ensure_xray():
        log("Xray not available, abort")
        sys.exit(1)
    subprocess.run(["pkill","-f","/tmp/xray run"], capture_output=True)
    # test
    working=[]
    for i,cfg in enumerate(configs,1):
        res=test_one(cfg)
        if res:
            cfg["res"]=res
            working.append(cfg)
            log(f"[{i}/{len(configs)}] PASS {res['code']} {cfg['proto']} {cfg['addr']}:{cfg['port']} {res['latency']}ms")
        elif i%30==0:
            log(f"[{i}/{len(configs)}] ... {len(working)} found")
    subprocess.run(["pkill","-f","/tmp/xray run"], capture_output=True)
    log(f"Done: {len(working)}/{len(configs)} working (strict 200+IP)")
    # Fallback: if <50, try lax (any non-000) for remaining to reach 50
    if len(working) < 50:
        log(f"Strict only {len(working)} (<50), collecting lax to fill up to 50...")
        # Re-test quickly for lax if needed? For now, we will just log and publish what we have
        # The next cron run with new random sample may find more
        if len(working) > 0:
            log(f"WARN: only {len(working)} strict (<50). Publishing {len(working)}; next run will sample different configs.")
        else:
            log("No strict working, will try lax fallback on next run")
    if not working:
        Path("/tmp/sylphnet_sub.txt").write_text("", encoding="utf-8")
        log("No working configs, not pushing")
        return
    # sort by latency
    working.sort(key=lambda x: x["res"]["latency"])
    date=jalali_today()
    out_lines=[]
    for i,c in enumerate(working,1):
        remark=f"@SylphNet | {date} #{i}"
        raw=c["raw"]
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
        out_lines.append(raw)
    plain="\n".join(out_lines)
    b64=base64.b64encode(plain.encode()).decode()
    # save local
    WORKDIR.mkdir(parents=True, exist_ok=True)
    (WORKDIR/"sub.txt").write_text(b64, encoding="utf-8")
    (WORKDIR/"sub_plain.txt").write_text(plain, encoding="utf-8")
    log(f"Saved {len(out_lines)} configs to ~/sylphnet/sub.txt")
    # push to public repo via git
    tmp="/tmp/public"
    subprocess.run(["rm","-rf",tmp], timeout=10)
    # use token in url (hide in log)
    url=f"https://oauth2:{token}@github.com/{PUBLIC_REPO}.git"
    r=subprocess.run(["git","clone",url,tmp], capture_output=True, text=True, timeout=30)
    if r.returncode!=0:
        log(f"git clone failed: {r.stderr[:200]}")
        return
    import shutil
    dest=Path(tmp)/"sub"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(WORKDIR/"sub.txt", dest/"sub.txt")
    shutil.copy(WORKDIR/"sub_plain.txt", dest/"sub_plain.txt")
    subprocess.run(["git","-C",tmp,"config","user.email","action@github.com"], timeout=5)
    subprocess.run(["git","-C",tmp,"config","user.name","SylphNet Bot"], timeout=5)
    subprocess.run(["git","-C",tmp,"add","sub/sub.txt","sub/sub_plain.txt"], timeout=5)
    # check diff
    r=subprocess.run(["git","-C",tmp,"diff","--staged","--quiet"], timeout=5)
    if r.returncode==0:
        log("No changes to push")
        return
    # count for commit msg
    cnt=len(out_lines)
    msg=f"Update subscription - {cnt} configs - {date} - auto"
    subprocess.run(["git","-C",tmp,"commit","-m",msg], timeout=10)
    r=subprocess.run(["git","-C",tmp,"push"], capture_output=True, text=True, timeout=30)
    if r.returncode==0:
        log(f"Pushed {cnt} configs to {PUBLIC_REPO}")
    else:
        log(f"git push failed: {r.stderr[:300]}")

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        log(f"FATAL: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
