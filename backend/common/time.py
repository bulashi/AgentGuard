from __future__ import annotations

import time


def now_unix() -> int:
    return int(time.time())
