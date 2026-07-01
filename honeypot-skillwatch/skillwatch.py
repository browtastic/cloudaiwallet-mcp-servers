#!/usr/bin/env python3
"""Honeypot skill-deployment watcher.
Polls npm-global + common skill install dirs for NEW packages an attacker deploys,
captures package.json + file tree + entry code, logs structured records for R&D."""
import os, json, time, hashlib, subprocess
from datetime import datetime, timezone

WATCH_DIRS = [
    "/usr/lib/node_modules",                                  # npm -g
    "/root/.openclaw/workspace/skills",                       # openclaw workspace skills
    "/root/skills", "/opt/skills",                            # common clawhub --dir targets
]
# also scan sandbox skill dirs created by clawhub default-cwd installs
SANDBOX_GLOB = "/root/.openclaw/sandboxes"
OUT = "/var/log/cloudaiwallet/skill-deployments.jsonl"
BASELINE = "/opt/honeypot-skillwatch/baseline.json"
# packages present at first run / known-legit — never flag these
IGNORE = {"npm","corepack","openclaw","supergateway","promptfoo","clawhub","node_modules"}
# auto-suppress ALL bundled openclaw skills by name (they appear in every fresh sandbox)
BUNDLED_DIR = "/usr/lib/node_modules/openclaw/skills"
try:
    IGNORE |= set(os.listdir(BUNDLED_DIR))
except Exception:
    pass
MAX_CODE = 4000

# ---- skill archival (additive; never blocks watcher/emit) ----
ARCHIVE_DIR = "/var/lib/honeypot-skill-archive"
S3_CAPTURES = "s3://cloudaiwallet-backup-<AWS_ACCOUNT_ID>/mvp6honey/captures/skills/"

def archive_skill(skill_path, slug):
    """Snapshot a skill dir to local tgz + async S3 push. Best-effort; swallows all errors.
    Snapshots BEFORE emit so it wins the race vs an attacker rm -rf."""
    try:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in str(slug))[:80]
        tgz = os.path.join(ARCHIVE_DIR, ts + "-" + safe + ".tgz")
        parent = os.path.dirname(skill_path.rstrip("/")) or "/"
        base = os.path.basename(skill_path.rstrip("/"))
        subprocess.run(["tar", "czf", tgz, "-C", parent, base],
                       timeout=60, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["aws", "s3", "cp", tgz, S3_CAPTURES + os.path.basename(tgz)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return tgz
    except Exception:
        return None

def now(): return datetime.now(timezone.utc).isoformat()

def snapshot_dirs():
    seen = set()
    dirs = list(WATCH_DIRS)
    # add per-session sandbox skills dirs
    try:
        for s in os.listdir(SANDBOX_GLOB):
            p = os.path.join(SANDBOX_GLOB, s, "skills")
            if os.path.isdir(p): dirs.append(p)
    except Exception: pass
    for d in dirs:
        try:
            for name in os.listdir(d):
                full = os.path.join(d, name)
                if os.path.isdir(full):
                    seen.add(full)
        except Exception: pass
    return seen

def capture(path):
    rec = {"_type":"skill_deployment","ts":now(),"path":path,"name":os.path.basename(path)}
    try:
        pj = os.path.join(path,"package.json")
        if os.path.exists(pj):
            with open(pj) as f: rec["package_json"] = json.load(f)
    except Exception as e: rec["package_json_error"]=str(e)
    # file tree (capped)
    files=[]
    try:
        for root,_,fns in os.walk(path):
            for fn in fns:
                fp=os.path.join(root,fn)
                try: sz=os.path.getsize(fp)
                except Exception: sz=-1
                files.append({"f":os.path.relpath(fp,path),"size":sz})
                if len(files)>=200: break
            if len(files)>=200: break
    except Exception: pass
    rec["files"]=files
    # grab likely entry-point / install-hook code (the dangerous bits)
    suspects=[]
    pjd = rec.get("package_json",{}) if isinstance(rec.get("package_json"),dict) else {}
    cand=set()
    if pjd.get("main"): cand.add(pjd["main"])
    if isinstance(pjd.get("bin"),dict): cand.update(pjd["bin"].values())
    if isinstance(pjd.get("bin"),str): cand.add(pjd["bin"])
    for s in ("index.js","install.js","postinstall.js","SKILL.md","skill-card.md",".clawhub/origin.json","_meta.json"): cand.add(s)
    # postinstall scripts = classic malware vector
    scripts = pjd.get("scripts",{}) if isinstance(pjd.get("scripts"),dict) else {}
    rec["npm_scripts"]=scripts
    for c in cand:
        fp=os.path.join(path,c)
        if os.path.isfile(fp):
            try:
                with open(fp,"r",errors="replace") as f: code=f.read(MAX_CODE)
                suspects.append({"file":c,"code":code})
            except Exception: pass
    # FALLBACK: if package.json unparseable or no entry captured, grab ALL script-like files
    SCRIPT_EXT=(".js",".mjs",".cjs",".ts",".py",".sh",".rb",".pl")
    captured_files={x["file"] for x in suspects}
    if rec.get("package_json_error") or not suspects:
        try:
            for root,_,fns in os.walk(path):
                for fn in fns:
                    if fn.endswith(SCRIPT_EXT):
                        rel=os.path.relpath(os.path.join(root,fn),path)
                        if rel in captured_files: continue
                        try:
                            with open(os.path.join(root,fn),"r",errors="replace") as f:
                                suspects.append({"file":rel,"code":f.read(MAX_CODE)})
                            captured_files.add(rel)
                        except Exception: pass
                        if len(suspects)>=20: break
                if len(suspects)>=20: break
        except Exception: pass
    rec["entry_code"]=suspects
    return rec

def signature(path):
    """Content signature = sorted (relpath,size) so we re-capture when files change (multi-step deploys)."""
    sig=[]
    try:
        for root,_,fns in os.walk(path):
            for fn in fns:
                fp=os.path.join(root,fn)
                try: sz=os.path.getsize(fp)
                except Exception: sz=-1
                sig.append((os.path.relpath(fp,path),sz))
    except Exception: pass
    return hashlib.md5(repr(sorted(sig)).encode()).hexdigest()

def main():
    if os.path.exists(BASELINE):
        baseline=set(json.load(open(BASELINE)))
    else:
        baseline=snapshot_dirs()
        json.dump(sorted(baseline),open(BASELINE,"w"))
    sigs={}   # path -> last content signature (in-memory; re-baselines on restart)
    while True:
        try:
            cur=snapshot_dirs()
            watch=[p for p in cur if os.path.basename(p) not in IGNORE]
            emit=[]
            for p in watch:
                sg=signature(p)
                if p not in baseline:
                    emit.append(p); sigs[p]=sg          # brand-new dir
                elif sigs.get(p) is not None and sigs.get(p)!=sg:
                    emit.append(p); sigs[p]=sg          # changed since last capture (race fix)
                elif p not in sigs:
                    sigs[p]=sg                           # baselined before restart; record sig, don't re-emit
            for p in emit:
                ap=archive_skill(p, os.path.basename(p))
                rec=capture(p)
                try: rec["archive_path"]=ap
                except Exception: pass
                with open(OUT,"a") as f: f.write(json.dumps(rec,default=str)+"\n")
            if emit:
                baseline |= set(emit) | cur
                json.dump(sorted(baseline),open(BASELINE,"w"))
        except Exception:
            pass
        time.sleep(15)

if __name__=="__main__":
    main()
