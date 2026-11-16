#!/usr/bin/env python3
"""Build a deterministic measured initrd; never start a guest or activate it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

POLICY = "processed-input-accepted-output-v1"


def static_elf(path):
    raw = Path(path).read_bytes()
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", raw, 18)[0] != 62:
        raise ValueError("expected an x86-64 ELF")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    if size < 56 or count < 1 or count > 2048 or offset + size * count > len(raw):
        raise ValueError("invalid ELF program headers")
    kinds = [struct.unpack_from("<I", raw, offset + size * i)[0] for i in range(count)]
    if 3 in kinds or 1 not in kinds:
        raise ValueError("measured guest binaries must be static")
    return raw


def cpio(entries):
    output = bytearray()
    for inode, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")], 1):
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        output += b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        output += encoded
        output += b"\0" * (-len(output) % 4)
        output += data
        output += b"\0" * (-len(output) % 4)
    return bytes(output)


def build(guest, engine, template, owner_key, model_sha256, drift_ppm):
    for value in (owner_key, model_sha256):
        if not re.fullmatch("[0-9a-f]{64}", value) or value == "0" * 64:
            raise ValueError("a configured public key and model digest are required")
    if not 1 <= drift_ppm <= 10000:
        raise ValueError("qualified drift allowance required")
    init = static_elf(guest)
    counted = static_elf(engine)
    if len(init) > 128 << 20 or len(counted) > 128 << 20:
        raise ValueError("guest binary too large")
    text = Path(template).read_bytes()
    text.decode("utf-8")
    if not text or len(text) > 16384 or b"\0" in text:
        raise ValueError("invalid fixed template")
    profile = dict(owner_key=owner_key, model_sha256=model_sha256,
                   tokenizer_sha256=model_sha256,
                   template_sha256=hashlib.sha256(text).hexdigest(),
                   runtime_sha256=hashlib.sha256(counted).hexdigest(),
                   policy_sha256=hashlib.sha256(POLICY.encode()).hexdigest(),
                   drift_ppm=drift_ppm)
    directories = ["dev", "etc", "etc/hypermesh-meter", "input", "journal", "proc", "run", "sys", "usr", "usr/bin"]
    entries = [(name, 0o040755, b"") for name in directories]
    entries += [("etc/resolv.conf", 0o100444, b"nameserver 10.0.2.3\n"),
                ("init", 0o100500, init),
                ("usr/bin/hypermesh-counted-cpu", 0o100500, counted),
                ("etc/hypermesh-meter/profile.json", 0o100400,
                 json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()),
                ("etc/hypermesh-meter/template.txt", 0o100400, text)]
    return cpio(sorted(entries)), profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("guest", "engine", "template", "owner-key", "model-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--drift-ppm", type=int, required=True)
    args = parser.parse_args()
    target = Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise ValueError("output directory must be empty")
    raw, profile = build(args.guest, args.engine, args.template,
                         args.owner_key, args.model_sha256, args.drift_ppm)
    (target / "initrd.cpio").write_bytes(raw)
    (target / "guest-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    (target / "artifact.json").write_text(json.dumps({
        "initrd_sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw), "profile": profile,
        "approved_measurement": None,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
