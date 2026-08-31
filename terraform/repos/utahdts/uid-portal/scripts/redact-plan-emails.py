#!/usr/bin/env python3
"""Redact email addresses from Terraform plan/apply output streams."""

from __future__ import annotations

import re
import sys


EMAIL_ADDRESS = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def redact(text: str) -> str:
    return EMAIL_ADDRESS.sub("<redacted-email>", text)


def main() -> None:
    for line in sys.stdin:
        sys.stdout.write(redact(line))


if __name__ == "__main__":
    main()
