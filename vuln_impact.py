#!/usr/bin/env python3
"""
vuln_impact.py - For a Gradle project, find vulnerable dependencies (via OSV.dev)
and classify how big the fix is: PATCH (safe) / MINOR (check) / MAJOR (breaking).

Usage:
    python vuln_impact.py /path/to/service
    python vuln_impact.py svc-a svc-b svc-c --json report.json
Exit code 1 if any MAJOR fix (or core-framework MINOR) is needed -> usable in CI.

No third-party packages required. Needs: gradle/gradlew on the machine + internet to api.osv.dev.
"""
import argparse, json, os, re, subprocess, sys, urllib.request
from functools import lru_cache

# Libraries where ANY non-patch bump is treated as high impact. Extend freely.
CORE_FRAMEWORKS = (
    "org.springframework.boot:", "org.springframework:", "org.springframework.security:",
    "org.springframework.cloud:", "org.hibernate", "io.quarkus:", "io.micronaut:",
    "jakarta.", "javax.", "org.apache.kafka:", "com.fasterxml.jackson",
)
OSV = "https://api.osv.dev/v1"


# ---------- Gradle dependency tree ----------
def run_gradle(project_dir, configuration):
    wrapper = os.path.join(project_dir, "gradlew")
    cmd = [wrapper if os.path.exists(wrapper) else "gradle", "-q", "dependencies",
           "--configuration", configuration]
    out = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[-500:])
    return out.stdout


def parse_tree(text):
    """Returns {(group:artifact, version): {"direct": bool, "via": set()}}"""
    deps, stack = {}, {}
    for line in text.splitlines():
        m = re.search(r"(\+---|\\---) (.+)$", line)
        if not m:
            continue
        depth = m.start() // 5
        body = re.sub(r"\s*\((\*|c|n)\)\s*$", "", m.group(2)).strip()
        if body.startswith("project "):
            continue
        left, _, resolved = body.partition(" -> ")
        parts = left.split(":")
        if len(parts) < 2:
            continue
        ga = f"{parts[0]}:{parts[1]}"
        version = resolved.strip() or (parts[2] if len(parts) > 2 else "")
        version = version.split(":")[-1] if ":" in version else version  # "g:a:1.0 -> g:a2:2.0"
        stack[depth] = ga
        if not version:
            continue
        info = deps.setdefault((ga, version), {"direct": False, "via": set()})
        if depth == 0:
            info["direct"] = True
        else:
            info["via"].add(stack.get(0, "?"))
    return deps


# ---------- Version helpers ----------
def vparse(v):
    nums = [int(x) for x in re.findall(r"\d+", re.split(r"[-+_]", v)[0])][:4]
    return tuple(nums + [0] * (3 - len(nums)))


def classify(cur, fixed):
    c, f = vparse(cur), vparse(fixed)
    if f[0] != c[0]:
        return "MAJOR"
    if f[1] != c[1]:
        return "MINOR"
    return "PATCH"


# ---------- OSV ----------
def http(url, payload=None):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode() if payload else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


@lru_cache(maxsize=None)
def vuln_detail(vid):
    return http(f"{OSV}/vulns/{vid}")


def min_fix_for(vuln, ga, current):
    """Lowest fixed version of the affected range that contains `current`."""
    cur, best = vparse(current), None
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "Maven" or pkg.get("name") != ga:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced = (0, 0, 0)
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = vparse(ev["introduced"])
                elif "fixed" in ev:
                    fixed = vparse(ev["fixed"])
                    if introduced <= cur < fixed and (best is None or fixed < vparse(best)):
                        best = ev["fixed"]
    return best


def scan(deps):
    keys = list(deps)
    findings = []
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        res = http(f"{OSV}/querybatch", {"queries": [
            {"package": {"name": ga, "ecosystem": "Maven"}, "version": v} for ga, v in chunk]})
        for (ga, ver), r in zip(chunk, res["results"]):
            for v in r.get("vulns", []):
                d = vuln_detail(v["id"])
                fix = min_fix_for(d, ga, ver)
                if not fix:
                    continue  # no known fix
                impact = classify(ver, fix)
                core = ga.startswith(CORE_FRAMEWORKS)
                findings.append({
                    "id": v["id"], "aliases": d.get("aliases", []), "library": ga,
                    "current": ver, "fixed_in": fix, "impact": impact,
                    "core_framework": core,
                    "direct": deps[(ga, ver)]["direct"],
                    "via": sorted(deps[(ga, ver)]["via"]),
                    "breaking": impact == "MAJOR" or (core and impact == "MINOR"),
                    "summary": d.get("summary", ""),
                })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("projects", nargs="+")
    ap.add_argument("--configuration", default="runtimeClasspath")
    ap.add_argument("--json", help="write full report to this file")
    ap.add_argument("--only-breaking", action="store_true",
                    help="summary lists only libraries needing a MAJOR/breaking change")
    a = ap.parse_args()

    report, any_breaking = {}, False
    for p in a.projects:
        print(f"\n=== {os.path.basename(os.path.abspath(p))} ===")
        try:
            deps = parse_tree(run_gradle(p, a.configuration))
            findings = scan(deps)
        except Exception as e:
            print(f"  ERROR: {e}")
            continue
        report[p] = findings
        if not findings:
            print("  no known fixable vulnerabilities")
        for f in sorted(findings, key=lambda x: (not x["breaking"], x["library"])):
            tag = "BREAKING" if f["breaking"] else "ok      "
            where = "direct" if f["direct"] else "via " + ", ".join(f["via"][:2])
            print(f"  [{tag}] {f['id']:<22} {f['library']} {f['current']} -> {f['fixed_in']} "
                  f"({f['impact']}, {where})")
            any_breaking |= f["breaking"]

    # ---- consolidated list: one row per library across all services ----
    agg = {}
    for proj, findings in report.items():
        name = os.path.basename(os.path.abspath(proj))
        for f in findings:
            row = agg.setdefault((f["library"], f["current"], f["fixed_in"]), {
                "impact": f["impact"], "breaking": f["breaking"],
                "services": set(), "ids": set()})
            row["services"].add(name)
            row["ids"].add(f["id"])
    rows = [(k, v) for k, v in agg.items() if v["breaking"] or not a.only_breaking]
    rows.sort(key=lambda kv: (not kv[1]["breaking"], kv[0][0]))
    print("\n=== SUMMARY (libraries with vulnerabilities) ===")
    for (lib, cur, fix), v in rows:
        tag = "BREAKING" if v["breaking"] else "ok"
        print(f"[{tag:<8}] {lib}  {cur} -> {fix}  ({v['impact']})"
              f"  vulns={len(v['ids'])}  services: {', '.join(sorted(v['services']))}")
    if not rows:
        print("nothing to report")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(report, fh, indent=2)
    sys.exit(1 if any_breaking else 0)


if __name__ == "__main__":
    main()
