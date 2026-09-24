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

LISTED = {"4e9a232b": None, "6b936f08": 1, "f29a3eb2": 2, "859d0e24": 3}

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

def version_report(boot_dir, boot_version, ex_versions):
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
    return line + "\n" + "".join(f"ex{i}\t{v}\n" for i, v in enumerate(ex_versions, 1))

class Expired(Exception):
    """The session was not accepted."""

class StaleBoot(Exception):
    """The boot report is behind what SE serves; poll.yml records the new version."""

def version_check(sid, from_version, report):
    """Returns the body, or None when SE answers 204 (nothing newer than from_version)."""
    url = f"https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game/{from_version}/{sid}"
    try:
        response = urllib.request.urlopen(urllib.request.Request(
            url, data=report.encode(),
            headers={"User-Agent": "FFXIV PATCH CLIENT", "X-Hash-Check": "enabled"}), timeout=180)
    except urllib.error.HTTPError as e:
        if e.code in (409, 410):
            raise StaleBoot(f"version check answered {e.code}") from e
        raise Expired(f"version check answered {e.code}") from e
    if response.status == 204:
        return None
    return body_of(response)

def parse_chain(body):
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

def latest_of(path, slug):
    repo = os.path.join(path, "repos", f"{slug}.json")
    return json.load(open(repo))["latest"] if os.path.exists(repo) else None

def catch_up_expansions(path, target, stamp):
    """SE never lists ex4/ex5 to a trial account, so a 204 says nothing about them."""
    added = {}
    for slug in EXPANSION_PATH:
        repo = os.path.join(path, "repos", f"{slug}.json")
        if not os.path.exists(repo) or latest_of(path, slug) >= target:
            continue
        got = extend_expansion(repo, slug, [target], stamp)
        if got:
            added[slug] = got
    return added

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".")
    ap.add_argument("--boot-dir", required=True)
    ap.add_argument("--boot-version", required=True)
    ap.add_argument("--sid-file")
    args = ap.parse_args()

    user, password = os.environ.get("SQEX_USER"), os.environ.get("SQEX_PASS")
    if not user or not password:
        raise SystemExit("SQEX_USER and SQEX_PASS must be set")

    sid = None
    if args.sid_file and os.path.exists(args.sid_file):
        sid = open(args.sid_file).read().strip() or None

    listed = [slug for slug in LISTED if LISTED[slug]]
    listed.sort(key=lambda slug: LISTED[slug])
    current = [latest_of(args.path, slug) for slug in listed]
    game = latest_of(args.path, "4e9a232b")

    # One cheap probe from where the index already stands; 204 means nothing newer.
    fresh_login = False
    for attempt in range(2):
        try:
            report = version_report(args.boot_dir, args.boot_version, current)
            body = version_check(sid, game, report) if sid else None
            if sid:
                break
        except StaleBoot as e:
            raise SystemExit(
                f"::error::boot report {args.boot_version} is stale ({e}); "
                "poll.yml records the new boot version, then this run succeeds")
        except Expired as e:
            print(f"cached session rejected ({e})")
            sid = None
        if sid is None:
            if attempt == 1:
                raise SystemExit("login failed twice; leaving the schedule to back off")
            sid, _ = session(user, password)
            fresh_login = True
            if args.sid_file:
                open(args.sid_file, "w").write(sid)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
                    fh.write("relogin=true\n")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if body is None:
        print(f"up to date at {game} (204)")
        caught = catch_up_expansions(args.path, game, stamp)
        for slug, versions in caught.items():
            print(f"  {slug}: +{len(versions)} confirmed on the CDN {versions}")
        return 0

    # Something moved, so rebuild the whole route from SE's own ordering.
    print("SE offers new patches, rebuilding from the sentinel")
    full = version_report(args.boot_dir, args.boot_version, [SENTINEL] * len(current))
    rows = parse_chain(version_check(sid, SENTINEL, full))
    by_slug = {}
    for row in rows:
        by_slug.setdefault(row["slug"], []).append(row)
    print(f"SE offers {len(rows)} patches across {len(by_slug)} repositories")

    new = []
    for slug, route in by_slug.items():
        repo = os.path.join(args.path, "repos", f"{slug}.json")
        if not os.path.exists(repo):
            print(f"  {slug}: not in the index, skipped")
            continue
        added, reparented, newest = apply_route(repo, route, stamp)
        new += added
        if added or reparented:
            print(f"  {slug}: +{len(added)} added, {reparented} re-parented, latest {newest}")

    for slug in EXPANSION_PATH:
        repo = os.path.join(args.path, "repos", f"{slug}.json")
        if os.path.exists(repo):
            added = extend_expansion(repo, slug, new, stamp)
            if added:
                print(f"  {slug}: +{len(added)} confirmed on the CDN {added}")

    for slug in list(by_slug) + list(EXPANSION_PATH):
        repo = os.path.join(args.path, "repos", f"{slug}.json")
        if os.path.exists(repo):
            dead = dead_on_chain(repo)
            if dead:
                print(f"::warning::{slug} chain passes through dead patches {dead}, needs a splice")
    return 0

if __name__ == "__main__":
    sys.exit(main())
