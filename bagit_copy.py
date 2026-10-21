#!/usr/bin/env python3
"""Create a BagIt bag from an existing payload or bag while preserving metadata order.

This wrapper script is intentionally conservative:
- source bags are validated before use
- if the source is an existing bag, only the payload directory is copied
- if the source is a plain directory, the whole directory tree is copied
- RFC 8493 defaults to SHA-512; this script enforces that when no algorithms are
  supplied because the upstream library defaults to sha256+sha512
- metadata is merged in the order: source bag -> info file -> command line
- metadata order is preserved when writing bag-info.txt because the upstream
  library sorts keys when saving
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from collections import OrderedDict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import bagit  # type: ignore  # noqa: E402

DEFAULT_HASHES = ["sha512"]


def _normalize_key(key: str) -> str:
    key = key.strip()
    if not key:
        raise ValueError("Bag metadata keys must not be empty")
    return key


def _coerce_value(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    # bag-info.txt values are plain text; strip CR/LF to avoid corrupting the file
    text = text.replace("\r", "").replace("\n", "")
    return text


def _set_or_append(mapping: OrderedDict[str, object], key: str, value: object) -> None:
    key = _normalize_key(key)
    if key in mapping:
        existing = mapping[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            mapping[key] = [existing, value]
    else:
        mapping[key] = value


def parse_key_value_entries(entries: list[str] | tuple[str, ...] | None) -> OrderedDict[str, object]:
    """Parse entries like ['Contact-Name: Alice', 'Bag-Count: 2'].

    Repeated keys are preserved as list values.
    """
    merged: OrderedDict[str, object] = OrderedDict()
    if not entries:
        return merged

    for raw_entry in entries:
        for candidate in str(raw_entry).split(","):
            item = candidate.strip()
            if not item:
                continue
            if ":" not in item:
                raise ValueError(
                    f"Invalid metadata entry {item!r}. Expected format 'Key: Value'."
                )
            key, value = item.split(":", 1)
            _set_or_append(merged, key, _coerce_value(value.strip()))

    return merged


def read_info_file(path: Path) -> OrderedDict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"Info file does not exist: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return OrderedDict()
    entries = [line.strip() for line in text.splitlines() if line.strip()]
    return parse_key_value_entries(entries)


def _looks_like_bag(path: Path) -> bool:
    return path.is_dir() and (path / "bagit.txt").is_file() and (path / "data").is_dir()


def validate_source_bag(source_path: Path) -> None:
    """Raise if the source bag is invalid.

    This is intentionally stricter than letting bag creation implicitly validate a
    broken input bag.
    """
    if not source_path.exists():
        raise FileNotFoundError(f"Source path does not exist: {source_path}")

    bag = bagit.Bag(str(source_path))
    bag.validate()


def copy_source_to_target(source_path: Path, target_path: Path) -> None:
    if target_path.exists():
        raise FileExistsError(
            f"Target path already exists: {target_path}. Please choose a new destination."
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)

    if _looks_like_bag(source_path):
        payload_dir = source_path / "data"
        for child in payload_dir.iterdir():
            shutil.copy2(child, target_path / child.name)
        return

    shutil.copytree(source_path, target_path, dirs_exist_ok=False)


def _custom_bag_info_writer(path: Path, bag_info: OrderedDict[str, object]) -> None:
    """Write bag-info.txt preserving insertion order.

    The upstream library writes bag-info.txt using sorted(bag_info.keys()), which
    reorders metadata. This helper preserves the order that the caller expects.
    """
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for key, values in bag_info.items():
            if not isinstance(values, list):
                values = [values]
            for value in values:
                text = _coerce_value(value)
                handle.write(f"{key}: {text}\n")


def _merge_metadata(*mappings: OrderedDict[str, object]) -> OrderedDict[str, object]:
    merged: OrderedDict[str, object] = OrderedDict()
    for mapping in mappings:
        for key, value in mapping.items():
            if key not in merged:
                merged[key] = value
            else:
                existing = merged[key]
                if isinstance(existing, list):
                    if isinstance(value, list):
                        existing.extend(value)
                    else:
                        existing.append(value)
                elif isinstance(value, list):
                    merged[key] = [existing]
                    merged[key].extend(value)
                else:
                    merged[key] = value
    return merged


def _build_metadata(source_bag_info: OrderedDict[str, object], info_file_entries: OrderedDict[str, object], cli_entries: OrderedDict[str, object]) -> OrderedDict[str, object]:
    merged = _merge_metadata(source_bag_info, info_file_entries, cli_entries)

    # Preserve library defaults only when they are not explicitly supplied.
    if "Bagging-Date" not in merged:
        merged["Bagging-Date"] = date.today().strftime("%Y-%m-%d")
    if "Bag-Software-Agent" not in merged:
        merged["Bag-Software-Agent"] = f"bagit.py v{bagit.VERSION} <{bagit.PROJECT_URL}>"

    # Payload-Oxum is generated by the library; if it already exists in the source bag
    # we keep the source value, otherwise we let make_bag() create it.
    return merged


def normalize_algorithms(raw_algorithms: list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize a list like ['sha512', 'sha256,sha1'] to a canonical list."""
    raw_values: list[str] = []
    for entry in raw_algorithms or []:
        raw_values.extend(part.strip() for part in str(entry).split(","))

    cleaned = [alg.lower() for alg in raw_values if alg and alg.strip()]
    if not cleaned:
        return DEFAULT_HASHES

    valid = []
    for alg in cleaned:
        if alg not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hashing algorithm: {alg}")
        if alg not in valid:
            valid.append(alg)
    return valid


def rewrite_tagmanifests_for_target(target_path: Path, algorithms: list[str]) -> None:
    """Regenerate tag manifests after a custom bag-info.txt write."""
    for algorithm in algorithms:
        bagit._make_tagmanifest_file(algorithm, str(target_path), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a BagIt bag from either an existing bag or a plain directory "
            "while preserving metadata order and validating source bags first."
        )
    )
    parser.add_argument("source_path", type=Path, help="Path to an existing bag or source directory")
    parser.add_argument("target_path", type=Path, help="Path where the new bag will be created")
    parser.add_argument("--info-file", type=Path, help="Text file containing key:value metadata entries")
    parser.add_argument(
        "--bag-info",
        dest="bag_info",
        action="append",
        default=[],
        help="Metadata entry in the form 'Key: Value'. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--algorithm",
        "--alg",
        "-a",
        dest="algorithms",
        action="append",
        default=[],
        help="Hash algorithm to include in the bag manifests. May be repeated or comma-separated.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    source_path = args.source_path.resolve()
    target_path = args.target_path.resolve()

    if source_path == target_path:
        raise ValueError("Source and target paths must be different.")

    if not source_path.exists():
        raise FileNotFoundError(f"Source path does not exist: {source_path}")

    # Source bag validation is required before creating a derived bag.
    if _looks_like_bag(source_path):
        validate_source_bag(source_path)
    elif source_path.is_file():
        raise ValueError(f"Source path must be a directory or a BagIt bag: {source_path}")

    source_metadata: OrderedDict[str, object] = OrderedDict()
    if _looks_like_bag(source_path):
        bag = bagit.Bag(str(source_path))
        source_metadata = OrderedDict(bag.info.items())

    info_file_entries = OrderedDict()
    if args.info_file:
        info_file_entries = read_info_file(args.info_file)

    cli_entries = parse_key_value_entries(args.bag_info)
    final_metadata = _build_metadata(source_metadata, info_file_entries, cli_entries)

    algorithms = normalize_algorithms(args.algorithms)
    copy_source_to_target(source_path, target_path)

    # bagit.make_bag() writes bag-info.txt in sorted key order; we explicitly rewrite it
    # afterward to preserve the desired insertion order.
    bag = bagit.make_bag(str(target_path), bag_info=final_metadata, checksums=algorithms)

    # Ensure the output bag-info.txt preserves the intended ordering.
    info_path = target_path / bag.tag_file_name
    _custom_bag_info_writer(info_path, final_metadata)

    # Because the file content changed, tag manifests must be regenerated.
    rewrite_tagmanifests_for_target(target_path, algorithms)

    # Final validation confirms the created bag is structurally valid.
    bag = bagit.Bag(str(target_path))
    bag.validate()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI failure path
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
"""
} Erotisk to=functions.create_or_update_file  <>