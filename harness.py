#!/usr/bin/env python3
"""
PurpleLab-lite harness (final)
Automates deployment, attack execution, log collection, detection, and reporting.
"""

import subprocess, time, os, json, datetime, shutil, sys

AUTO_CLEANUP = True
WAIT_SECS = 10

ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(ROOT, "logs")
HOST_UPLOADS = os.path.join(ROOT, "webroot", "uploads")
CONTAINER_UPLOADS = "/data/uploads"
DETECTIONS_DIR = os.path.join(ROOT, "detections")
REPORTS_DIR = os.path.join(ROOT, "reports")
REPORT = os.path.join(REPORTS_DIR, "report.md")

UPLOADS_DIR = CONTAINER_UPLOADS if os.path.isdir(CONTAINER_UPLOADS) else HOST_UPLOADS
SCAN_DIRS = [LOGS_DIR, UPLOADS_DIR]

def run(cmd, timeout=60, check=False):
    print(f"[+] Running: {cmd}")
    try:
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if r.stdout.strip(): print(r.stdout.strip())
        if r.stderr.strip(): print(r.stderr.strip(), file=sys.stderr)
        if check and r.returncode != 0:
            raise subprocess.CalledProcessError(r.returncode, cmd)
        return r
    except Exception as e:
        print(f"[!] Command failed: {e}")
        return None

def docker_available(): return shutil.which("docker") is not None
def start_compose(): docker_available() and run("docker compose up -d --build")
def stop_compose(): docker_available() and run("docker compose down --remove-orphans")

def exec_attacker():
    """
    Execute attacker scenario:
    - if docker available -> try `docker exec attacker ...` (no file redirection, collect_logs handles docker logs)
    - else -> run the local attack script and redirect stdout/stderr to logs/attacker_stdout.log
    """
    local_script = os.path.join(ROOT, "attacks", "run_attacks.sh")

    if docker_available():
        # try docker exec first; still capture its output to console (collect_logs will fetch docker logs separately)
        print("[*] Executing attacker inside container (docker exec)...")
        return run("docker exec attacker sh /attacks/run_attacks.sh || true")
    else:
        if os.path.exists(local_script):
            print("[*] Docker not available — running attack script locally and saving output to logs/attacker_stdout.log")
            try:
                os.chmod(local_script, 0o755)
            except Exception:
                pass
            # ensure logs dir exists
            os.makedirs(LOGS_DIR, exist_ok=True)
            log_path = os.path.join(LOGS_DIR, "attacker_stdout.log")
            # run the script and capture stdout/stderr to file (append with timestamp)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(f"\n\n=== Run at {datetime.datetime.now(datetime.timezone.utc).isoformat()} UTC ===\n")
                # use subprocess.Popen to stream output into file
                proc = subprocess.Popen(["sh", local_script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    fh.write(line)
                proc.wait()
            return None
        else:
            print("[!] No attacker script found to run locally.")
            return None


def collect_logs():
    """
    Ensure logs/uploads exist; collect docker container logs for juice and attacker if present.
    Also ensure logs/attacker_stdout.log exists (create empty if not present).
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    print("[*] Collecting logs...")

    # Always ensure an attacker log file exists so generate_report can include it even if empty
    attacker_log_path = os.path.join(LOGS_DIR, "attacker_stdout.log")
    if not os.path.exists(attacker_log_path):
        open(attacker_log_path, "a", encoding="utf-8").close()

    if docker_available():
        # collect docker container logs for juice and attacker if containers exist
        # use '|| true' so command never fails the harness
        run("docker logs juice > logs/juice_stdout.log 2>&1 || true")
        run("docker logs attacker > logs/attacker_stdout.log 2>&1 || true")
    else:
        print("[*] Docker not present: assuming logs/* and uploads/* already contain data or local run populated logs/attacker_stdout.log.")
    return 0

def run_yara():
    findings=[]
    rule_paths=[os.path.join(DETECTIONS_DIR,f) for f in os.listdir(DETECTIONS_DIR) if f.endswith((".yar",".yara"))]
    if not rule_paths: print("[!] No YARA rules found."); return findings
    try:
        import yara
        print("[+] Using yara-python")
        for rule_path in rule_paths:
            try: rules=yara.compile(filepath=rule_path)
            except Exception as e: print(f"[!] Failed to compile {rule_path}: {e}"); continue
            for scan_root in SCAN_DIRS:
                for root,_,files in os.walk(scan_root):
                    for f in files:
                        path=os.path.join(root,f)
                        try:
                            matches=rules.match(path)
                            if matches: findings.append({"file":path,"rule":os.path.basename(rule_path),"matches":[str(m) for m in matches]})
                        except: continue
        return findings
    except Exception:
        yarabin=shutil.which("yara")
        if not yarabin: print("[!] No YARA binary found."); return findings
        for rule_path in rule_paths:
            for scan_root in SCAN_DIRS:
                for root,_,files in os.walk(scan_root):
                    for f in files:
                        path=os.path.join(root,f)
                        r=run(f"{yarabin} -s {rule_path} {path}")
                        if r and r.stdout.strip(): findings.append({"file":path,"rule":os.path.basename(rule_path),"stdout":r.stdout})
        return findings

def grep_indicators():
    hits=[]; keywords=["evil-scanner","shell.php","IEX","mimikatz"]
    for scan_root in SCAN_DIRS:
        if not os.path.isdir(scan_root): continue
        for root,_,files in os.walk(scan_root):
            for f in files:
                path=os.path.join(root,f)
                try:
                    content=open(path,errors="ignore").read()
                    found=[k for k in keywords if k in content]
                    if found: hits.append({"file":path,"keywords":found})
                except: continue
    return hits

def generate_report(yara_findings, grep_hits):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    content=[]
    content.append("# 🧩 PurpleLab-lite Security Report\n\n")
    content.append(f"🕒 **Date (UTC):** {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n")
    content.append("## 🧾 Summary\n")
    content.append(f"- YARA matches: **{len(yara_findings)}**\n")
    content.append(f"- Keyword hits: **{len(grep_hits)}**\n\n")
    content.append("## 🔍 YARA Findings\n")
    if yara_findings:
        for f in yara_findings:
            content.append(f"- **File:** `{f['file']}`\n  - Rule: `{f.get('rule','N/A')}`\n  - Matches: `{', '.join(f.get('matches',[]))}`\n")
        content.append("\n")
    else: content.append("_No YARA detections found._\n\n")
    content.append("## 🪶 Grep Indicators\n")
    if grep_hits:
        for g in grep_hits:
            content.append(f"- **File:** `{g['file']}`\n  - Keywords: {', '.join(g['keywords'])}\n")
        content.append("\n")
    else: content.append("_No suspicious keywords found._\n\n")
    # include attacker logs snippet
    attacker_log=os.path.join(LOGS_DIR,"attacker_stdout.log")
    if os.path.exists(attacker_log):
        content.append("## 💀 Attacker Logs (snippet)\n")
        snippet="".join(open(attacker_log,"r",errors="ignore").readlines()[:30])
        content.append(f"```\n{snippet}\n```\n")
    content.append("---\n✅ **Analysis complete** - generated by PurpleLab-lite harness.\n")
    with open(REPORT,"w",encoding="utf-8") as f: f.writelines(content)
    print(f"[+] Report generated at {REPORT}")

def cleanup_uploads_volume():
    if not AUTO_CLEANUP: print("[*] AUTO_CLEANUP disabled."); return
    if not docker_available(): print("[!] Docker not found - skipping AUTO_CLEANUP."); return
    print("[*] AUTO_CLEANUP: clearing uploads Docker volume...")
    run('docker run --rm -v uploads:/data alpine sh -c "rm -f /data/* || true"')
    print("[+] AUTO_CLEANUP: uploads volume cleared.")

if __name__=="__main__":
    print("[*] Starting PurpleLab-lite harness...")
    if docker_available():
        start_compose()
        print(f"[*] Waiting {WAIT_SECS}s for services...")
        time.sleep(WAIT_SECS)
    else: print("[!] Docker not detected - skipping container startup.")
    print("[*] Executing attack scenario...")
    exec_attacker()
    time.sleep(5)
    print("[*] Collecting logs...")
    collect_logs()
    print("[*] Running detections (YARA + grep)...")
    generate_report(run_yara(), grep_indicators())
    print("[*] Stopping containers...")
    if docker_available(): stop_compose()
    cleanup_uploads_volume()
    print("[+] Done. Check reports/report.md.")
