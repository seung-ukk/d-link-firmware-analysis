"""Reproduce the DIR-882 extraction in separately inspectable stages.

Only directories and regular files are extracted from CPIO. Symlink targets and
special entries are recorded in the inventory; prepare_rootfs.py resolves
library links into ordinary files for the isolated emulators.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes.fromhex("c05fbf1936c99429ce2a0781f08d6ad8")
FIRMWARE = {
    "original": {
        "zip": "firmware/original.zip",
        "zip_sha256": "fe85902d34cbeae8340fb6f9bf05117d445bcedf3fc6b8b017c3bedf2baff86a",
        "bin": "DIR882A1_FW130B06.bin",
        "bin_sha256": "573ab7ae729c44ef9c4aa52941f5b0ec1d44dd4c2d921cc461a6cb912c40e4d9",
        "cpio_bytes": 46324736,
        "cpio_entries": 1693,
    },
    "hotfix_b03": {
        "zip": "firmware/hotfix_b03.zip",
        "zip_sha256": "79e8712201b40ea128b8e776d7d0c02c0ae25e58b60d0b02d3d928eaa2cea5d1",
        "bin": "DIR882A1_FW1.30B06.bin",
        "bin_sha256": "d39ff294506b1f58592cfd30bbc4e690f43bc4d366dcaed5bf3be50a2dc21587",
        "cpio_bytes": 46490112,
        "cpio_entries": 1693,
    },
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as out:
        out.write(data)


def names(label: str) -> tuple[dict, Path, Path]:
    spec = FIRMWARE[label]
    folder = ROOT / "analysis" / label
    image = folder / spec["bin"]
    return spec, folder, image


def verify(label: str) -> None:
    spec, _, _ = names(label)
    archive = ROOT / spec["zip"]
    raw = archive.read_bytes()
    actual = digest(raw)
    if actual != spec["zip_sha256"]:
        raise ValueError(f"Unexpected ZIP SHA-256: {actual}")
    with zipfile.ZipFile(archive) as zf:
        if zf.testzip():
            raise ValueError("ZIP CRC check failed")
        members = zf.infolist()
        found = [member.filename for member in members]
        if spec["bin"] not in found or len(found) != 2:
            raise ValueError(f"Unexpected ZIP members: {found}")
        print(f"{label}: ZIP SHA-256 {actual}; ZIP CRC OK")
        for member in members:
            print(f"  {member.filename}: {member.file_size} bytes")


def unzip(label: str) -> None:
    verify(label)
    spec, folder, _ = names(label)
    with zipfile.ZipFile(ROOT / spec["zip"]) as zf:
        for member in zf.infolist():
            if member.filename != Path(member.filename).name:
                raise ValueError("ZIP contains a directory path")
            data = zf.read(member)
            if member.filename == spec["bin"] and digest(data) != spec["bin_sha256"]:
                raise ValueError("Unexpected BIN SHA-256")
            put_new(folder / member.filename, data)
            print(f"extracted {folder.relative_to(ROOT) / member.filename}")


def decrypt(label: str) -> None:
    spec, folder, image = names(label)
    raw = image.read_bytes()
    if digest(raw) != spec["bin_sha256"] or raw[:4] != b"SHRS":
        raise ValueError("BIN identity or SHRS header differs")
    plain_len, cipher_len = struct.unpack(">II", raw[4:12])
    encrypted = raw[1756 : 1756 + cipher_len]
    if len(encrypted) != cipher_len or cipher_len % 16:
        raise ValueError("Encrypted payload is incomplete")
    if hashlib.sha512(encrypted).digest() != raw[156:220]:
        raise ValueError("Encrypted SHA-512 check failed")
    dec = Cipher(algorithms.AES(KEY), modes.CBC(raw[12:28])).decryptor()
    plain = (dec.update(encrypted) + dec.finalize())[:plain_len]
    if hashlib.sha512(plain).digest() != raw[92:156]:
        raise ValueError("Plaintext SHA-512 check failed")
    if hashlib.sha512(plain + KEY).digest() != raw[28:92]:
        raise ValueError("Plaintext-plus-key SHA-512 check failed")
    if plain[:4] != bytes.fromhex("27051956"):
        raise ValueError("uImage header missing")
    dest = folder / (image.stem + ".decrypted.bin")
    put_new(dest, plain)
    print(f"{label}: SHRS checks 3 passed; uImage {len(plain)} bytes; SHA-256 {digest(plain)}")


def kernel(label: str) -> None:
    _, folder, image = names(label)
    plain = (folder / (image.stem + ".decrypted.bin")).read_bytes()
    data_len = struct.unpack(">I", plain[12:16])[0]
    if len(plain) - 160 != data_len:
        raise ValueError("uImage data length differs")
    unpacked = lzma.decompress(plain[160:], format=lzma.FORMAT_ALONE)
    put_new(folder / (image.stem + ".decrypted.unpacked"), unpacked)
    print(f"{label}: compressed {data_len}; unpacked kernel {len(unpacked)} bytes; SHA-256 {digest(unpacked)}")


def initramfs(label: str) -> None:
    spec, folder, image = names(label)
    unpacked = (folder / (image.stem + ".decrypted.unpacked")).read_bytes()
    for match in re.finditer(b"\x5d\x00\x00", unpacked):
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            candidate = dec.decompress(unpacked[match.start() :], max_length=100_000_000)
        except lzma.LZMAError:
            continue
        if candidate.startswith(b"070701") and dec.eof:
            if len(candidate) != spec["cpio_bytes"]:
                raise ValueError("CPIO size differs")
            put_new(folder / "initramfs.cpio", candidate)
            print(f"{label}: LZMA offset {match.start()}; CPIO {len(candidate)} bytes; magic 070701")
            return
    raise ValueError("No matching LZMA-compressed CPIO found")


def rootfs(label: str) -> None:
    spec, folder, _ = names(label)
    raw = (folder / "initramfs.cpio").read_bytes()
    out = folder / "rootfs"
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    records: list[dict] = []
    counts: Counter[str] = Counter()
    pos = 0
    while True:
        if raw[pos : pos + 6] not in (b"070701", b"070702"):
            raise ValueError(f"Invalid CPIO header at {pos}")
        h = [int(raw[pos + 6 + i * 8 : pos + 14 + i * 8], 16) for i in range(13)]
        ino, mode, _, _, links, _, size, _, _, _, _, namesize, _ = h
        if namesize < 1 or namesize > 4096:
            raise ValueError("Invalid CPIO name length")
        name_bytes = raw[pos + 110 : pos + 110 + namesize]
        if not name_bytes.endswith(b"\0"):
            raise ValueError("CPIO name is not terminated")
        name = name_bytes[:-1].decode("utf-8")
        data_start = (pos + 110 + namesize + 3) & ~3
        content = raw[data_start : data_start + size]
        if len(content) != size:
            raise ValueError("Truncated CPIO entry")
        pos = (data_start + size + 3) & ~3
        if name == "TRAILER!!!":
            break
        rel = PurePosixPath(name)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise ValueError(f"Unsafe CPIO path: {name}")
        dest = out.joinpath(*rel.parts)
        record = {
            "path": name, "mode": oct(mode), "size": size,
            "inode": ino, "links": links, "sha256": digest(content),
        }
        if stat.S_ISDIR(mode):
            dest.mkdir(parents=True, exist_ok=True)
            counts["directories"] += 1
        elif stat.S_ISREG(mode):
            put_new(dest, content)
            dest.chmod(mode & 0o777)
            counts["regular files"] += 1
        elif stat.S_ISLNK(mode):
            record["symlink_target"] = content.decode("utf-8", errors="replace")
            counts["symlinks listed, not created"] += 1
        else:
            counts["special entries listed, not created"] += 1
        records.append(record)
    if len(records) != spec["cpio_entries"]:
        raise ValueError(f"Unexpected CPIO entry count: {len(records)}")
    inventory = folder / "rootfs_inventory.json"
    put_new(inventory, (json.dumps(records, indent=2) + "\n").encode())
    print(f"{label}: entries {len(records)}; " +
          ", ".join(f"{key} {value}" for key, value in counts.items()))
    print(f"rootfs: {out.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("verify", "unzip", "decrypt", "kernel", "initramfs", "rootfs"))
    parser.add_argument("label", choices=tuple(FIRMWARE))
    args = parser.parse_args()
    globals()[args.stage](args.label)


if __name__ == "__main__":
    main()
