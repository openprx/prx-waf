#!/usr/bin/env python3
"""
sync.py — Remote rule sync tool for prx-waf

Clones or updates rule repositories (e.g., OWASP CRS), converts rules to
prx-waf YAML format using modsec2yaml.py, and reports new/updated/removed rules.

Usage:
    python3 tools/sync.py --source owasp-crs --output rules/owasp-crs/
    python3 tools/sync.py --source owasp-crs --tag v4.10.0 --output rules/owasp-crs/
    python3 tools/sync.py --source owasp-crs --output rules/owasp-crs/ --dry-run

Configuration: rules/sync-config.yaml
"""

import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("sync")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_repo_root() -> Path:
    """Walk up from the script location to find the project root (contains rules/)."""
    current = Path(__file__).resolve().parent
    for candidate in [current, current.parent, current.parent.parent]:
        if (candidate / "rules").is_dir():
            return candidate
    raise RuntimeError(
        "Could not locate project root (directory containing rules/). "
        "Run sync.py from the project root or tools/ directory."
    )


def load_sync_config(repo_root: Path) -> dict:
    config_path = repo_root / "rules" / "sync-config.yaml"
    if not config_path.exists():
        raise FileNotFoundError(f"Sync config not found: {config_path}")
    with open(config_path) as f:
        return yaml.safe_load(f)


def file_hash(path: Path) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_yaml_hashes(directory: Path) -> dict[str, str]:
    """Return {relative_path: sha256} for all .yaml files in directory."""
    result = {}
    if not directory.exists():
        return result
    for p in sorted(directory.rglob("*.yaml")):
        result[str(p.relative_to(directory))] = file_hash(p)
    return result


def run(cmd: list[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------

def clone_or_update(repo_url: str, dest: Path, branch: str, tag: Optional[str] = None) -> str:
    """
    Clone the repository to dest if it doesn't exist, or fetch+reset if it does.
    Returns the resolved commit SHA.
    """
    if dest.exists() and (dest / ".git").exists():
        log.info("Repository already cloned at %s — fetching updates...", dest)
        run(["git", "fetch", "--tags", "--prune"], cwd=dest)
    else:
        log.info("Cloning %s (branch: %s) to %s...", repo_url, branch, dest)
        dest.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--depth=1", "--branch", branch, repo_url, str(dest)])

    # Checkout specific tag or latest branch tip
    if tag:
        log.info("Checking out tag: %s", tag)
        run(["git", "checkout", tag], cwd=dest)
    else:
        run(["git", "checkout", branch], cwd=dest)
        run(["git", "reset", "--hard", f"origin/{branch}"], cwd=dest)

    # Return commit SHA for provenance tracking
    result = run(["git", "rev-parse", "HEAD"], cwd=dest)
    commit_sha = result.stdout.strip()
    log.info("HEAD commit: %s", commit_sha)
    return commit_sha


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def find_converter(repo_root: Path, converter_path: str) -> Path:
    """Resolve converter script path relative to repo root."""
    converter = repo_root / converter_path
    if not converter.exists():
        raise FileNotFoundError(
            f"Converter script not found: {converter}\n"
            "Ensure tools/modsec2yaml.py exists in the project."
        )
    return converter


def convert_rules(
    converter: Path,
    source_dir: Path,
    output_dir: Path,
    dry_run: bool = False,
) -> list[Path]:
    """
    Run modsec2yaml.py on each .conf file in source_dir.
    Returns list of output .yaml files that were written.
    """
    conf_files = sorted(source_dir.glob("*.conf"))
    if not conf_files:
        log.warning("No .conf rule files found in %s", source_dir)
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for conf_file in conf_files:
        out_name = conf_file.stem + ".yaml"
        out_path = output_dir / out_name

        if dry_run:
            log.info("[DRY-RUN] Would convert: %s -> %s", conf_file.name, out_path)
            written.append(out_path)
            continue

        try:
            result = run(
                [sys.executable, str(converter), str(conf_file), "--output", str(out_path)]
            )
            if result.returncode == 0:
                log.debug("Converted: %s -> %s", conf_file.name, out_name)
                written.append(out_path)
            else:
                log.warning(
                    "Converter failed for %s:\n%s", conf_file.name, result.stderr
                )
        except subprocess.CalledProcessError as e:
            log.error("Converter error for %s: %s", conf_file.name, e.stderr)

    return written


# ---------------------------------------------------------------------------
# Diff reporting
# ---------------------------------------------------------------------------

def compute_diff(
    before: dict[str, str],
    after: dict[str, str],
) -> tuple[list[str], list[str], list[str]]:
    """
    Compare before/after hash maps.
    Returns (new_files, updated_files, removed_files).
    """
    before_keys = set(before.keys())
    after_keys = set(after.keys())

    new_files = sorted(after_keys - before_keys)
    removed_files = sorted(before_keys - after_keys)
    updated_files = sorted(
        k for k in (before_keys & after_keys) if before[k] != after[k]
    )

    return new_files, updated_files, removed_files


def print_diff_report(
    source_name: str,
    new_files: list[str],
    updated_files: list[str],
    removed_files: list[str],
    commit_sha: str,
    dry_run: bool,
) -> None:
    prefix = "[DRY-RUN] " if dry_run else ""
    print()
    print(f"{'=' * 60}")
    print(f"{prefix}Sync Report for source: {source_name}")
    print(f"{'=' * 60}")
    print(f"  Commit: {commit_sha}")
    print(f"  New rules files   : {len(new_files)}")
    print(f"  Updated rule files: {len(updated_files)}")
    print(f"  Removed rule files: {len(removed_files)}")
    print()

    if new_files:
        print("  NEW:")
        for f in new_files:
            print(f"    + {f}")

    if updated_files:
        print("  UPDATED:")
        for f in updated_files:
            print(f"    ~ {f}")

    if removed_files:
        print("  REMOVED:")
        for f in removed_files:
            print(f"    - {f}")

    if not new_files and not updated_files and not removed_files:
        print("  No changes detected. Rules are already up to date.")

    print()


# ---------------------------------------------------------------------------
# Main sync logic
# ---------------------------------------------------------------------------

def sync_source(
    source_name: str,
    source_config: dict,
    repo_root: Path,
    output_override: Optional[str],
    tag_override: Optional[str],
    dry_run: bool,
) -> None:
    repo_url = source_config["repo"]
    branch = source_config.get("branch", "main")
    rules_path = source_config.get("rules_path", "rules/")
    output_path = output_override or source_config.get("output", f"rules/{source_name}/")
    converter_path = source_config.get("converter", "tools/modsec2yaml.py")
    tag = tag_override or source_config.get("tag")

    output_dir = repo_root / output_path
    converter = find_converter(repo_root, converter_path)

    # Snapshot existing output state before sync
    before_hashes = collect_yaml_hashes(output_dir)

    with tempfile.TemporaryDirectory(prefix=f"prx-waf-sync-{source_name}-") as tmpdir:
        clone_dest = Path(tmpdir) / source_name
        commit_sha = clone_or_update(repo_url, clone_dest, branch, tag)

        source_rules_dir = clone_dest / rules_path
        if not source_rules_dir.exists():
            log.error("Rules path not found in repo: %s", source_rules_dir)
            sys.exit(1)

        # Convert rules
        log.info("Converting rules from %s to %s...", source_rules_dir, output_dir)
        converted = convert_rules(converter, source_rules_dir, output_dir, dry_run=dry_run)
        log.info("Converted %d rule files.", len(converted))

    # Snapshot output state after sync
    after_hashes = collect_yaml_hashes(output_dir) if not dry_run else before_hashes

    new_files, updated_files, removed_files = compute_diff(before_hashes, after_hashes)
    print_diff_report(
        source_name, new_files, updated_files, removed_files, commit_sha, dry_run
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sync.py",
        description="Sync remote rule sources (e.g., OWASP CRS) into prx-waf YAML format.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync latest OWASP CRS from main branch
  python3 tools/sync.py --source owasp-crs --output rules/owasp-crs/

  # Sync a specific tagged release
  python3 tools/sync.py --source owasp-crs --tag v4.10.0 --output rules/owasp-crs/

  # Dry run: show what would change without writing files
  python3 tools/sync.py --source owasp-crs --output rules/owasp-crs/ --dry-run

  # List available sources from sync-config.yaml
  python3 tools/sync.py --list
""",
    )
    parser.add_argument(
        "--source",
        help="Source name as defined in rules/sync-config.yaml (e.g., owasp-crs).",
    )
    parser.add_argument(
        "--output",
        help="Override the output directory from config.",
    )
    parser.add_argument(
        "--tag",
        help="Checkout a specific git tag (e.g., v4.10.0). Overrides branch.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing any files.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available sources from sync-config.yaml and exit.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        repo_root = find_repo_root()
        config = load_sync_config(repo_root)
    except (FileNotFoundError, RuntimeError) as e:
        log.error("%s", e)
        sys.exit(1)

    sources = config.get("sources", {})

    # --list
    if args.list:
        print("\nAvailable sync sources (from rules/sync-config.yaml):\n")
        for name, cfg in sources.items():
            desc = cfg.get("description", "No description")
            print(f"  {name}: {desc}")
            print(f"    repo  : {cfg.get('repo', 'N/A')}")
            print(f"    branch: {cfg.get('branch', 'main')}")
            print(f"    output: {cfg.get('output', 'N/A')}")
            print()
        sys.exit(0)

    if not args.source:
        log.error("--source is required. Use --list to see available sources.")
        sys.exit(1)

    if args.source not in sources:
        log.error(
            "Source '%s' not found in sync-config.yaml. Available: %s",
            args.source,
            ", ".join(sources.keys()),
        )
        sys.exit(1)

    try:
        sync_source(
            source_name=args.source,
            source_config=sources[args.source],
            repo_root=repo_root,
            output_override=args.output,
            tag_override=args.tag,
            dry_run=args.dry_run,
        )
    except FileNotFoundError as e:
        log.error("File not found: %s", e)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log.error("Subprocess failed: %s\n%s", e.cmd, e.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
