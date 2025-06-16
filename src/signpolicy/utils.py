import os
import subprocess
import hashlib
from rich.console import Console
from rich.table import Table
from rich import box

def hash_file(filepath, algo):
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()

def get_secret_keys(gpg_bin="gpg"):
    """Returns a set of key IDs for which secret keys exist."""
    try:
        result = subprocess.run(
            [gpg_bin, "--list-secret-keys", "--with-colons"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        secret_keys = set()
        for line in result.stdout.splitlines():
            if line.startswith("sec"):
                parts = line.split(":")
                if len(parts) > 4:
                    key_id = parts[4]
                    secret_keys.add(key_id)
        return secret_keys
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error listing secret keys:[/red] {e.stderr}")
        return set()

def process_policy(date, dry_run=False, no_color=False):
    global console
    console = Console(force_terminal=not no_color, no_color=no_color)

    user = os.getenv("USER")
    gpg_bin = os.getenv("GPGBIN", "gpg")
    policy = f"{user}.{date}"

    if not os.path.isfile(policy):
        console.print(f"[red]Policy {policy} not found[/red]")
        return

    console.print(f"[bold green]Policy {policy} found[/bold green]")

    with open(policy) as f:
        lines = f.readlines()

    secret_keys = get_secret_keys(gpg_bin)
    keys = []
    for line in lines:
        if line.startswith("pub") and "revoked:" not in line:
            keyid = line.split()[1].split("/")[-1]
            keys.append(keyid)

    summary = {
        "found_keys": keys,
        "signed_keys": [],
        "skipped_keys": [],
        "verified_keys": [],
        "errors": [],
    }

    signatures_successful = False

    for key in keys:
        short_key = key[-8:]
        sig_file = f"{policy}.{short_key}.sig"
        if not os.path.isfile(sig_file):
            if key not in secret_keys:
                summary["skipped_keys"].append(key)
                console.print(f"[yellow][SKIP][/yellow] No secret key for {key}")
                continue
            if dry_run:
                console.print(f"[cyan][DRY-RUN][/cyan] Would sign policy with key {key}")
                summary["signed_keys"].append(key)
                signatures_successful = True
            else:
                subprocess.run([gpg_bin, "-qbu", f"{key}!", policy])
                asc_file = f"{policy}.asc"
                if os.path.isfile(asc_file):
                    os.rename(asc_file, sig_file)
                    result = subprocess.run([gpg_bin, "--verify", sig_file, policy])
                    if result.returncode == 0:
                        summary["signed_keys"].append(key)
                        signatures_successful = True
                    else:
                        console.print(f"[red][ERROR][/red] Verification failed after signing with {key}")
                        summary["errors"].append(key)
                else:
                    console.print(f"[red][ERROR][/red] No .asc file generated for {key}")
                    summary["errors"].append(key)
        else:
            if dry_run:
                console.print(f"[cyan][DRY-RUN][/cyan] Would verify existing signature: {sig_file}")
                summary["verified_keys"].append(key)
                signatures_successful = True
            else:
                result = subprocess.run([gpg_bin, "--verify", sig_file, policy])
                if result.returncode == 0:
                    summary["verified_keys"].append(key)
                    signatures_successful = True
                else:
                    console.print(f"[red][ERROR][/red] Signature verification failed: {sig_file}")
                    summary["errors"].append(key)

    if signatures_successful and not dry_run:
        for algo in ["md5", "sha1", "sha256"]:
            with open(f"{algo}sums", "a") as f:
                f.write(f"{hash_file(policy, algo)}  {policy}\n")
        console.print("[green][INFO][/green] Checksums written.")
    elif dry_run:
        console.print("[cyan][DRY-RUN][/cyan] Checksums would be written if not in dry-run mode.")
    else:
        console.print("[yellow][WARN][/yellow] No valid signatures. Checksums skipped.")

    # Final summary
    table = Table(title="Summary", box=box.SIMPLE_HEAVY)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Keys found", str(len(summary["found_keys"])))
    table.add_row("Keys signed", str(len(summary["signed_keys"])))
    table.add_row("Keys verified", str(len(summary["verified_keys"])))
    table.add_row("Keys skipped", str(len(summary["skipped_keys"])))
    table.add_row("Errors", str(len(summary["errors"])))

    console.print()
    console.print(table)
