from __future__ import annotations

import argparse
from pathlib import Path

from backend.crypto.sm import generate_keypair

KEY_NAMES = (
    "authorization",
    "agent-coordinator",
    "agent-knowledge",
    "agent-case",
    "agent-refund",
    "gateway",
    "receipt",
    "audit",
)


def write_if_missing(path: Path, value: str) -> None:
    if path.exists():
        return
    path.write_text(value + "\n", encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local AgentGuard development keys")
    parser.add_argument("--root", default="keys")
    args = parser.parse_args()

    root = Path(args.root)
    private_dir = root / "private"
    public_dir = root / "public"
    private_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    for name in KEY_NAMES:
        private_path = private_dir / f"{name}.private"
        public_path = public_dir / f"{name}.public"
        if private_path.exists() and public_path.exists():
            continue
        pair = generate_keypair()
        write_if_missing(private_path, pair.private_key_hex)
        write_if_missing(public_path, pair.public_key_hex)

    print(f"Development keys are present under {root.resolve()}")


if __name__ == "__main__":
    main()
