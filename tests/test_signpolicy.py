import os
import tempfile
from signpolicy.utils import hash_file, process_policy

def test_hash_file():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("test content\n")
        fname = f.name
    try:
        assert hash_file(fname, "md5") == "d6eb32081c822ed572b70567826d9d9d"
        assert hash_file(fname, "sha1") == "4fe2b8dd12cd9cd6a413ea960cd8c09c25f19527"
        assert hash_file(fname, "sha256") == "a1fff0ffefb9eace7230c24e50731f0a91c62f9cefdfe77121c2f607125dffae"
    finally:
        os.remove(fname)

def test_process_policy_dry_run(monkeypatch, capsys):
    # Set up fake environment
    monkeypatch.setenv("USER", "testuser")

    # Create mock policy file
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        date = "20250616"
        policy_file = f"testuser.{date}"
        with open(policy_file, "w") as f:
            f.write("pub rsa2048/FAKEKEYID 2025-01-01 [SC]\n")

        # Run in dry-run mode
        process_policy(date, dry_run=True, no_color=True)

        output = capsys.readouterr().out
        assert "Would sign policy" in output or "Would verify existing" in output or "No secret key" in output
