#!/usr/bin/env python3
"""Refresh the global repositories from SE's authenticated version check.

The other regions poll unauthenticated in poll.yml. The global game and expansion repositories
need a logged-in session, so they are refreshed here instead. Writes files only; the workflow
commits.
"""
import argparse, datetime, gzip, hashlib, json, os, re, sys, urllib.error
import urllib.parse, urllib.request, zlib
from collections import OrderedDict

SENTINEL = "2012.01.01.0000.0000"
BOOT_FILES = ["ffxivboot.exe", "ffxivboot64.exe", "ffxivlauncher.exe",
              "ffxivlauncher64.exe", "ffxivupdater.exe", "ffxivupdater64.exe"]
# A trial account's maxex hides these, so each version is confirmed on the CDN instead.
EXPANSION_PATH = {"1bf99b87": "ex4", "6cfeab11": "ex5"}

def body_of(resp):
    raw = resp.read()
    enc = (resp.headers.get("content-encoding") or "").lower()
    if enc == "gzip":
        raw = gzip.decompress(raw)
    elif enc == "deflate":
        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw.decode("utf-8", "replace")

def session(user, password):
    """Returns (sid, maxex). The password is used here and never logged."""
    digest = hashlib.sha1("fourierasriellinux8".encode("utf-16-le")).digest()[:4]
    computer_id = f"{(-sum(digest)) & 0xff:02x}{digest.hex()}"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d-%H-%M")
    base = {
        "User-Agent": f"SQEXAuthor/2.0.0(Windows 6.2; ja-jp; {computer_id})",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-us",
        "Origin": "https://launcher.finalfantasyxiv.com",
        "Referer": f"https://launcher.finalfantasyxiv.com/v620/index.html?rc_lang=en_us&time={stamp}",
    }
    accept = ("image/gif, image/jpeg, image/pjpeg, application/x-ms-application, "
              "application/xaml+xml, application/x-ms-xbap, */*")
    top = ("https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top"
           "?lng=en&rgn=3&isft=1&cssmode=1&isnew=1&launchver=3")
    page = body_of(urllib.request.urlopen(urllib.request.Request(
        top, headers={**base, "Accept": accept, "Cookie": '_rsid=""'}), timeout=60))
    stored = re.search(r'name="_STORED_" value="([^"]+)"', page)
    if not stored:
        raise SystemExit("login/top did not return _STORED_")
    data = urllib.parse.urlencode({"_STORED_": stored.group(1), "sqexid": user,
                                   "password": password, "otppw": ""}).encode()
    out = body_of(urllib.request.urlopen(urllib.request.Request(
        "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/login.send", data=data,
        headers={**base, "Accept": accept, "Referer": top, "Cache-Control": "no-cache",
                 "Cookie": '_rsid=""'}), timeout=60))
    call = re.search(r'window\.external\.user\("login=auth,(.*?)"\);', out, re.S)
    if not call:
        raise SystemExit("login did not return an auth callback")
    parts = call.group(1).split(",")
    if parts[0] != "ok":
        raise SystemExit("login rejected; a game update usually invalidates the boot report")
    return parts[2], int(parts[14])

def version_report(boot_dir, boot_version, maxex):
    """`<bootver>=<name>/<size>/<sha1>,...` then one ex line each, as the client sends it."""
    reports = []
    for name in BOOT_FILES:
        path = os.path.join(boot_dir, name)
        if os.path.exists(path):
            blob = open(path, "rb").read()
            reports.append(f"{name}/{len(blob)}/{hashlib.sha1(blob).hexdigest()}")
    if not reports:
        raise SystemExit(f"no boot files found under {boot_dir}")
    line = boot_version + "=" + ",".join(reports)
    return line + "\n" + "".join(f"ex{i}\t{SENTINEL}\n" for i in range(1, maxex + 1))

def se_chain(sid, report):
    url = f"https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game/{SENTINEL}/{sid}"
    body = body_of(urllib.request.urlopen(urllib.request.Request(
        url, data=report.encode(),
        headers={"User-Agent": "FFXIV PATCH CLIENT", "X-Hash-Check": "enabled"}), timeout=180))
    rows = []
    for line in body.splitlines():
        f = line.split("\t")
        if len(f) >= 6 and f[-1].strip().startswith("http"):
            rows.append({"size": int(f[0]), "version": f[4], "url": f[-1].strip(),
                         "slug": f[-1].strip().split("/")[-2]})
    return rows

def head(url):
    try:
        r = urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "FFXIV PATCH CLIENT"}, method="HEAD"), timeout=30)
        return r.status, int(r.headers.get("Content-Length") or 0)
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception:
        return None, 0

def entry(prev, size, url, stamp, method):
    return OrderedDict([
        ("prev", prev), ("size", size), ("header", None),
        ("sources", OrderedDict([("cdn", OrderedDict(
            [("url", url), ("status", "alive"), ("checked", stamp)]))])),
        ("discovered", OrderedDict([("at", stamp), ("method", method)])),
        ("verified", None)])

def insert_after(patches, version, prev, record):
    out = OrderedDict()
    for key, value in patches.items():
        out[key] = value
        if key == prev:
            out[version] = record
    if version not in out:
        out[version] = record
    return out

def apply_route(path, route, stamp):
    doc = json.load(open(path), object_pairs_hook=OrderedDict)
    patches, added, reparented = doc["patches"], [], 0
    for i, row in enumerate(route):
        version, prev = row["version"], route[i - 1]["version"] if i else None
        if version not in patches:
            patches = insert_after(patches, version, prev,
                                   entry(prev, row["size"], row["url"], stamp, "version_check"))
            added.append(version)
        elif patches[version].get("prev") != prev:
            patches[version]["prev"] = prev
            reparented += 1
    doc["patches"], doc["latest"] = patches, route[-1]["version"]
    json.dump(doc, open(path, "w"), indent=2)
    open(path, "a").write("\n")
    return added, reparented, doc["latest"]

def extend_expansion(path, slug, versions, stamp):
    doc = json.load(open(path), object_pairs_hook=OrderedDict)
    patches, added = doc["patches"], []
    for version in versions:
        if version in patches:
            continue
        url = f"http://patch-dl.ffxiv.com/game/{EXPANSION_PATH[slug]}/{slug}/D{version}.patch"
        status, size = head(url)
        if status != 200:
            continue
        prev = doc["latest"]
        patches = insert_after(patches, version, prev, entry(prev, size, url, stamp, "cdn_sweep"))
        doc["latest"] = version
        added.append(version)
    if added:
        doc["patches"] = patches
        json.dump(doc, open(path, "w"), indent=2)
        open(path, "a").write("\n")
    return added

def dead_on_chain(path):
    doc = json.load(open(path))
    patches, cur, seen, dead = doc["patches"], doc["latest"], set(), []
    while cur and cur in patches and cur not in seen:
        seen.add(cur)
        sources = patches[cur].get("sources", {})
        if sources and all(s.get("status") == "dead" for s in sources.values()):
            dead.append(cur)
        cur = patches[cur].get("prev")
    return dead

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".")
    ap.add_argument("--boot-dir", required=True)
    ap.add_argument("--boot-version", required=True)
    args = ap.parse_args()

    user, password = os.environ.get("SQEX_USER"), os.environ.get("SQEX_PASS")
    if not user or not password:
        raise SystemExit("SQEX_USER and SQEX_PASS must be set")

    sid, maxex = session(user, password)
    report = version_report(args.boot_dir, args.boot_version, maxex)
    rows = se_chain(sid, report)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    by_slug = {}
    for row in rows:
        by_slug.setdefault(row["slug"], []).append(row)
    print(f"SE offers {len(rows)} patches across {len(by_slug)} repositories (maxex={maxex})")

    fresh = []
    for slug, route in by_slug.items():
        path = os.path.join(args.path, "repos", f"{slug}.json")
        if not os.path.exists(path):
            print(f"  {slug}: not in the index, skipped")
            continue
        added, reparented, latest = apply_route(path, route, stamp)
        fresh += added
        if added or reparented:
            print(f"  {slug}: +{len(added)} added, {reparented} re-parented, latest {latest}")

    for slug in EXPANSION_PATH:
        path = os.path.join(args.path, "repos", f"{slug}.json")
        if os.path.exists(path):
            added = extend_expansion(path, slug, fresh, stamp)
            if added:
                print(f"  {slug}: +{len(added)} confirmed on the CDN {added}")

    for slug in list(by_slug) + list(EXPANSION_PATH):
        path = os.path.join(args.path, "repos", f"{slug}.json")
        if os.path.exists(path):
            dead = dead_on_chain(path)
            if dead:
                print(f"::warning::{slug} chain passes through dead patches {dead}, needs a splice")
    return 0

if __name__ == "__main__":
    sys.exit(main())
