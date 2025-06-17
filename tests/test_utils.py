from pathlib import Path
from rich.console import Console
from signpolicy.utils import (
    parse_pub_keys,
    write_or_update_line,
    handle_key,
    Context,
    KeyResult,
)


# ---------------------------------------------------------------------------
# parse_pub_keys
# ---------------------------------------------------------------------------

def test_parse_pub_keys_excludes_revoked():
    block = (
        "pub rsa2048/0xABCDEF12 2020-01-01 [SC]\n"
        "uid Test User <a@b.c>\n"
        "pub rsa4096/0xDEADBEEF 2014-04-08 [revoked: 2021-06-15]\n"
        "pub rsa3072/12345678 2021-06-01 [SC]\n"
    )
    assert parse_pub_keys(block) == ["ABCDEF12", "12345678"]


# ---------------------------------------------------------------------------
# write_or_update_line
# ---------------------------------------------------------------------------

def test_write_or_update_line_replaces_existing(tmp_path):
    sums = tmp_path / "sha1sums"
    policy_a = "testuser.20250101"
    old = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  " + policy_a
    new = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  " + policy_a

    # seed file with a different hash + another policy line
    sums.write_text(old + "\ncccccccccccccccccccccccccccccccccccccccc  other.policy\n")

    # run helper – should *replace* the old line, keep the other
    write_or_update_line(sums, new)

    lines = sums.read_text().splitlines()
    assert new in lines
    assert old not in lines
    assert any("other.policy" in ln for ln in lines)


# ---------------------------------------------------------------------------
# handle_key  (dry‑run paths so no real GPG interaction is required)
# ---------------------------------------------------------------------------

def _make_ctx(tmpdir: Path, policy_name: str) -> Context:
    policy_path = tmpdir / policy_name
    policy_path.write_text("dummy\n")
    return Context(
        user="testuser",
        policy=policy_path,
        gpg_bin="gpg",               # never invoked in these dry‑run tests
        console=Console(no_color=True, record=True),
    )


def test_handle_key_skip_when_no_secret(tmp_path):
    ctx = _make_ctx(tmp_path, "policy.txt")
    result = handle_key(ctx, key="12345678", secret_keys=set(), dry=True)
    assert result is KeyResult.SKIPPED


def test_handle_key_signed_in_dry_run(tmp_path):
    ctx = _make_ctx(tmp_path, "policy.txt")
    result = handle_key(ctx, key="12345678", secret_keys={"12345678"}, dry=True)
    assert result is KeyResult.SIGNED


def test_handle_key_verified_when_sig_exists(tmp_path):
    key = "12345678"
    ctx = _make_ctx(tmp_path, "policy.txt")

    # create dummy signature file so handle_key treats it as “already signed”
    sig_path = ctx.policy.with_suffix(f"{ctx.policy.suffix}.{key[-8:]}.sig")
    sig_path.touch()

    result = handle_key(ctx, key=key, secret_keys={"12345678"}, dry=True)
    assert result is KeyResult.VERIFIED
