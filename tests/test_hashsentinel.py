import json
import tempfile
import unittest
from pathlib import Path
from hashsentinel import sha256_file, build_manifest, verify_manifest

class TestHashSentinel(unittest.TestCase):
    def test_sha256_known_value(self):
        with tempfile.TemporaryDirectory() as temp:
            file_path = Path(temp) / "hello.txt"
            file_path.write_text("hello", encoding="utf-8")
            self.assertEqual(
                sha256_file(file_path),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            )

    def test_manifest_and_verify_unchanged_file(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "a.txt").write_text("alpha", encoding="utf-8")
            manifest = build_manifest(folder)
            manifest_path = folder / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            results = verify_manifest(manifest_path)
            self.assertEqual(results[0]["status"], "OK")

    def test_detect_modified_file(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            target = folder / "a.txt"
            target.write_text("before", encoding="utf-8")
            manifest = build_manifest(folder)
            manifest_path = folder / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            target.write_text("after", encoding="utf-8")
            results = verify_manifest(manifest_path)
            self.assertEqual(results[0]["status"], "CHANGED")

    def test_detect_missing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            target = folder / "a.txt"
            target.write_text("temporary", encoding="utf-8")
            manifest = build_manifest(folder)
            manifest_path = folder / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            target.unlink()
            results = verify_manifest(manifest_path)
            self.assertEqual(results[0]["status"], "MISSING")

if __name__ == "__main__":
    unittest.main()
