from __future__ import annotations
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import List, Dict, Set
from rich.console import Console
from rich.table import Table
from rich import box


"""Utility helpers for signing, verifying and checksumming GPG policy files.

The module purposefully favours small, single‑responsibility helpers to keep
cyclomatic complexity low and make unit‑testing easier.
"""


__all__ = [
    "process_policy",
    "hash_file",
    "get_secret_keys",
    "parse_pub_keys",
]

ALGOS: tuple[str, ...] = ("md5", "sha1", "sha256")

py310 = sys.version_info.minor >= 10 or sys.version_info.major > 3


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(**({"slots": True} if py310 else {}))
class Context:
    """Execution context passed around instead of many individual args."""

    user: str
    policy: Path  # full path to policy file
    gpg_bin: str
    console: Console


class KeyResult(Enum):
    """Outcome for a single key-processing attempt."""

    SIGNED = auto()
    VERIFIED = auto()
    SKIPPED = auto()
    ERROR = auto()

    def label(self) -> str:  # for summary printout
        return self.name.capitalize()


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def hash_file(path: Path, algo: str) -> str:
    """Return *hex* digest of *path* using hashlib *algo*."""
    h = hashlib.new(algo)
    h.update(path.read_bytes())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# GPG helpers
# ---------------------------------------------------------------------------


def get_secret_keys(gpg_bin: str = "gpg") -> Set[str]:
    """Return a set of key‑ids for which secret keys are available."""
    try:
        proc = subprocess.run(
            [gpg_bin, "--list-secret-keys", "--with-colons"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        Console().print(f"[red]Error listing secret keys:[/red] {exc.stderr}")
        return set()

    result: Set[str] = set()
    for line in proc.stdout.splitlines():
        if line.startswith("sec"):
            # spec: field 5 is the key‑id (index 4)
            parts = line.split(":", maxsplit=5)
            if len(parts) > 4:
                result.add(parts[4])
    return result


def parse_pub_keys(pub_block: str) -> List[str]:
    """Extract key‑ids (without leading 0x) from a *pub* key listing."""
    keys: List[str] = []
    for line in pub_block.splitlines():
        if line.startswith("pub") and "revoked:" not in line:
            key_id = line.split()[1].split("/")[-1]
            if key_id.startswith("0x"):
                keys.append(key_id[2:])  # strip leading 0x
            else:
                keys.append(key_id)
    return keys


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def write_or_update_line(file_path: Path, new_line: str) -> None:
    """Append *new_line* to *file_path* unless the policy already has an entry.

    If an entry for the same policy filename exists, it is replaced with the
    new hash so there is never more than one checksum line per policy.
    """
    file_path.touch(exist_ok=True)
    policy_name = new_line.split()[-1]  # last token is the policy filename

    lines: List[str] = file_path.read_text().splitlines()
    with file_path.open("w") as fp:
        replaced = False
        for ln in lines:
            if ln.strip().endswith(policy_name):
                if not replaced:
                    fp.write(new_line + "\n")
                    replaced = True
            else:
                fp.write(ln + "\n")
        if not replaced:
            fp.write(new_line + "\n")


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def handle_key(ctx: Context, key: str, secret_keys: Set[str], dry: bool) -> KeyResult:
    """Sign or verify *key* for *ctx.policy*. Returns a :class:`KeyResult`."""
    c = ctx.console
    short = key[-8:]
    policy_suffix = ctx.policy.suffix
    sig_file = ctx.policy.with_suffix(f"{policy_suffix}.{short}.sig")

    # Case 1 – signature missing ⇒ potentially sign
    if not sig_file.exists():
        if key not in secret_keys:
            c.print(f"[yellow][SKIP][/yellow] No secret key for {key}")
            return KeyResult.SKIPPED
        if dry:
            c.print(f"[cyan][DRY][/cyan] would sign with {key}")
            return KeyResult.SIGNED

        # real signing
        subprocess.run([ctx.gpg_bin, "-qbu", f"{key}!", ctx.policy.name])
        asc_file = ctx.policy.with_suffix(f"{policy_suffix}.asc")
        if not asc_file.exists():
            c.print(f"[red]No .asc generated for {key}[/red]")
            return KeyResult.ERROR
        asc_file.rename(sig_file)

    # At this point we must verify (either existing or newly created sig)
    if dry:
        c.print(f"[cyan][DRY][/cyan] would verify {sig_file.name}")
        return KeyResult.VERIFIED

    result = subprocess.run([ctx.gpg_bin, "--verify", sig_file.name, ctx.policy.name])
    return KeyResult.VERIFIED if result.returncode == 0 else KeyResult.ERROR


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def write_checksums(ctx: Context) -> None:
    """Write or update checksum lines for *ctx.policy* using *ALGOS*."""
    for algo in ALGOS:
        checksum = hash_file(ctx.policy, algo)
        line = f"{checksum}  {ctx.policy.name}"
        write_or_update_line(Path(f"{algo}sums"), line)
    ctx.console.print("[green]Checksums updated.[/green]")


# ---------------------------------------------------------------------------
# Orchestration – the public entry point
# ---------------------------------------------------------------------------


def process_policy(date: str, *, dry_run: bool = False, no_color: bool = False) -> None:
    """Sign/verify policy *<USER>.<date>* and maintain checksum files.

    Parameters
    ----------
    date
        Date string in YYYYMMDD format that forms the policy filename.
    dry_run
        If *True*, no files are modified; actions are only logged.
    no_color
        Disable Rich colour output (useful for scripts/CI logs).
    """
    console = Console(force_terminal=not no_color, no_color=no_color)

    user = os.getenv("USER") or "policy"
    gpg_bin = os.getenv("GPGBIN", "gpg")
    policy = Path(f"{user}.{date}")

    if not policy.exists():
        console.print(f"[red]Policy {policy} not found.[/red]")
        return

    console.print(f"[bold green]Policy {policy} found.[/bold green]")

    ctx = Context(user, policy, gpg_bin, console)

    # ------------------------------------------------------------------
    # gather inputs
    # ------------------------------------------------------------------
    pub_keys_text = policy.read_text()
    keys = parse_pub_keys(pub_keys_text)
    secret_keys = get_secret_keys(gpg_bin)

    # ------------------------------------------------------------------
    # process each key
    # ------------------------------------------------------------------
    counts: Dict[KeyResult, int] = {k: 0 for k in KeyResult}
    for key in keys:
        outcome = handle_key(ctx, key, secret_keys, dry_run)
        counts[outcome] += 1

    success = counts[KeyResult.SIGNED] + counts[KeyResult.VERIFIED] > 0

    if success and not dry_run:
        write_checksums(ctx)
    elif dry_run:
        console.print("[cyan][DRY][/cyan] Would update checksums.")
    else:
        console.print("[yellow]No valid signatures – checksums not updated.[/yellow]")

    # ------------------------------------------------------------------
    # summary output
    # ------------------------------------------------------------------
    table = Table(title="Summary", box=box.SIMPLE_HEAVY)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Keys found", str(len(keys)))
    for kr in KeyResult:
        table.add_row(kr.label(), str(counts[kr]))

    console.print()
    console.print(table)
