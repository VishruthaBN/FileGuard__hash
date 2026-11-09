## FILEGUARD

FileGuard is a small Python file-integrity checker. It creates a baseline manifest of SHA-256 hashes for a file or directory, then checks later whether files are unchanged, modified, or missing.

## Features

- SHA-256 hashing using Python's standard library
- Processes large files in chunks
- Creates JSON manifests for files and directories
- Detects changed and missing files
- Exit code `1` when verification finds a problem
- Unit tests for hashing and integrity checks

## Requirements

- Python 3.10+
- No third-party dependencies

## Usage

Create a baseline for a directory:

```bash
python hashsentinel.py create ./important-files -o baseline.json
```

Verify it later:

```bash
python hashsentinel.py verify baseline.json
```

Create a baseline for one file:

```bash
python hashsentinel.py create ./notes.txt -o notes-baseline.json
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## How it works

1. Reads each file in 1 MiB chunks.
2. Calculates a SHA-256 digest.
3. Stores each relative path, digest, and file size in a JSON manifest.
4. Recalculates hashes during verification and reports `OK`, `CHANGED`, or `MISSING`.

## Important security note

A hash manifest detects accidental or unauthorized file changes only if the manifest itself is trusted. An attacker who can modify both the files and the manifest may hide tampering. Store trusted manifests separately or protect them with access controls. SHA-256 is a cryptographic hash, not encryption.

## Learning goals

This project demonstrates hashing, file I/O, JSON serialization, command-line interfaces, chunked processing, test-driven verification, and basic integrity monitoring.
