from __future__ import annotations

import re

from gmssl import sm2


def valid_public_point(public_key_hex: str) -> bool:
    if (
        not isinstance(public_key_hex, str)
        or re.fullmatch(r"[0-9a-f]{128}", public_key_hex) is None
    ):
        return False
    curve = sm2.default_ecc_table
    p, a, b = (int(curve[name], 16) for name in ("p", "a", "b"))
    x, y = int(public_key_hex[:64], 16), int(public_key_hex[64:], 16)
    return 0 <= x < p and 0 <= y < p and (y * y - x * x * x - a * x - b) % p == 0
