#!/usr/bin/env python3
"""Build deterministic placeholder ZIPs for initial Lambda provisioning."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def write_zip(path: Path, entries: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as archive:
        for name, content in sorted(entries.items()):
            info = ZipInfo(name, date_time=FIXED_TIMESTAMP)
            info.external_attr = 0o644 << 16
            archive.writestr(info, content, compress_type=ZIP_DEFLATED)


def main() -> None:
    write_zip(
        ROOT / "assets" / "lambda-placeholder.zip",
        {
            "lambda_function.py": (
                "def handler(event, context):\n"
                "    return {'statusCode': 503, 'body': 'Deployment pending'}\n"
            )
        },
    )
    write_zip(
        ROOT / "assets" / "layer-placeholder.zip",
        {"python/README.txt": "Placeholder layer; application CI publishes dependencies.\n"},
    )


if __name__ == "__main__":
    main()
