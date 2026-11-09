#!/usr/bin/env python3
"""HashSentinel: create and verify SHA-256 file integrity manifests."""
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

CHUNK_SIZE = 1024 * 1024

def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()

def build_manifest(target):
    target = Path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    files = [target] if target.is_file() else sorted(
        item for item in target.rglob("*") if item.is_file()
    )
    entries = []
    for item in files:
        entries.append({
            "path": str(item.relative_to(target.parent if target.is_file() else target)),
            "sha256": sha256_file(item),
            "size_bytes": item.stat().st_size,
        })
    return {
        "algorithm": "SHA-256",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(target),
        "files": entries,
    }

def verify_manifest(manifest_path):
    manifest_path = Path(manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = Path(data["target"])
    results = []
    for entry in data["files"]:
        file_path = root.parent / entry["path"] if root.is_file() else root / entry["path"]
        if not file_path.exists() or not file_path.is_file():
            state = "MISSING"
        elif sha256_file(file_path) != entry["sha256"]:
            state = "CHANGED"
        else:
            state = "OK"
        results.append({"path": entry["path"], "status": state})
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Create and verify SHA-256 file integrity manifests."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a baseline manifest")
    create.add_argument("target", help="File or directory to fingerprint")
    create.add_argument("-o", "--output", default="hashsentinel-manifest.json")

    verify = sub.add_parser("verify", help="Verify files against a manifest")
    verify.add_argument("manifest", help="Path to a manifest JSON file")

    args = parser.parse_args()

    try:
        if args.command == "create":
            manifest = build_manifest(args.target)
            Path(args.output).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            print(f"Manifest created: {args.output}")
            print(f"Files recorded: {len(manifest['files'])}")
        else:
            results = verify_manifest(args.manifest)
            for item in results:
                print(f"{item['status']:<8} {item['path']}")
            changed = sum(item["status"] != "OK" for item in results)
            print(f"\nVerified: {len(results) - changed}/{len(results)} unchanged")
            if changed:
                raise SystemExit(1)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
