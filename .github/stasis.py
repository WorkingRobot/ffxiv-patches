#!/usr/bin/env python3
"""Write stasis.json: the version report and lobby constants TemporalStasis logs in with.

Reads versions from the index, hashes the boot files and the game exe given to it, and pulls the
lobby constants out of that exe. Writes nothing unless every field was found.
"""
import argparse, base64, hashlib, json, os, re, struct, sys

BOOT = "2b5cbc63"
GAME = "4e9a232b"
EXPANSIONS = ["6b936f08", "f29a3eb2", "859d0e24", "1bf99b87", "6cfeab11"]
BOOT_FILES = ["ffxivboot.exe", "ffxivboot64.exe", "ffxivlauncher64.exe", "ffxivupdater64.exe"]

# Two RIP-relative movups loading the 32 character phrase in halves.
PHRASE = re.compile(rb"\x0f\x10[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})\x0f\x11..\x0f\x10[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})", re.S)
# The key struct: 0x12345678 magic at +8, version at +10h.
BLOWFISH = re.compile(rb"\xc7[\x40-\x47]\x08\x78\x56\x34\x12.{0,48}?\xc7[\x40-\x47]\x10(.{4})", re.S)
# LoginEx: client language at +8, then the version at +0Ah through the same base register.
LOGIN = re.compile(rb"\x66\x89([\x40-\x47])\x08.{0,8}?\xb8(..)\x00\x00\x66\x89\1\x0a", re.S)

def report(path):
    blob = open(path, "rb").read()
    return {"FileName": os.path.basename(path), "FileSize": len(blob),
            "Sha1Hash": base64.b64encode(hashlib.sha1(blob).digest()).decode()}

def only(found, what):
    if len(set(found)) != 1:
        raise SystemExit(f"::error::{what}: expected one value, found {sorted(set(found))}")
    return found[0]

def constants(exe):
    data = open(exe, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    count, optional = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<IIII", data, pe + 24 + optional + 40 * i + 8) for i in range(count)]

    def rva(offset):
        return next(va + offset - raw for _, va, size, raw in sections if raw <= offset < raw + size)

    def at(address, length):
        return next((data[raw + address - va:raw + address - va + length]
                     for _, va, size, raw in sections if va <= address < va + size), b"")

    phrases = []
    for m in PHRASE.finditer(data):
        first = rva(m.end(1)) + struct.unpack("<i", m.group(1))[0]
        second = rva(m.end(2)) + struct.unpack("<i", m.group(2))[0]
        if second != first + 16:
            continue
        text = at(first, 32)
        if re.fullmatch(rb"[0-9a-f]{32}", text):
            phrases.append(text.decode())
    return {
        "BlowfishPhrase": only(phrases, "blowfish phrase"),
        "BlowfishVersion": only([struct.unpack("<I", m.group(1))[0] for m in BLOWFISH.finditer(data)],
                                "blowfish version"),
        "LoginVersion": only([struct.unpack("<H", m.group(2))[0] for m in LOGIN.finditer(data)],
                             "login version"),
    }

def latest(path, slug):
    return json.load(open(os.path.join(path, "repos", f"{slug}.json")))["latest"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".")
    ap.add_argument("--boot-dir", required=True)
    ap.add_argument("--exe", required=True)
    args = ap.parse_args()

    stasis = {
        **constants(args.exe),
        "BootVersion": latest(args.path, BOOT),
        "GameVersion": latest(args.path, GAME),
        "ExVersions": [latest(args.path, slug) for slug in EXPANSIONS],
        "GameExe": report(args.exe),
        "BootHashes": [report(os.path.join(args.boot_dir, name)) for name in BOOT_FILES],
    }
    out = os.path.join(args.path, "stasis.json")
    json.dump(stasis, open(out, "w"), indent=2)
    open(out, "a").write("\n")
    print(json.dumps({k: stasis[k] for k in ("BlowfishPhrase", "BlowfishVersion", "LoginVersion",
                                              "GameVersion")}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
