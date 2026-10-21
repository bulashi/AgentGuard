from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg


def psycopg_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


@contextmanager
def connect(url: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(psycopg_url(url)) as connection:
        yield connection
