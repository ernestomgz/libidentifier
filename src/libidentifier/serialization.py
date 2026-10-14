"""Deterministic JSON without copying dataclass trees or entire output strings."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import fields, is_dataclass
from pathlib import Path


def iter_json(value):
    if is_dataclass(value):
        yield "{"
        for i, field in enumerate(sorted(fields(value), key=lambda f: f.name)):
            if i:
                yield ","
            yield json.dumps(field.name) + ":"
            yield from iter_json(getattr(value, field.name))
        yield "}"
    elif isinstance(value, dict):
        yield "{"
        for i, key in enumerate(sorted(value)):
            if i:
                yield ","
            yield json.dumps(key, ensure_ascii=False) + ":"
            yield from iter_json(value[key])
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for i, item in enumerate(value):
            if i:
                yield ","
            yield from iter_json(item)
        yield "]"
    else:
        yield json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def write_stream(value, stream):
    for chunk in iter_json(value):
        stream.write(chunk)
    stream.write("\n")


def write_json(value, path):
    destination = Path(path)
    fd, name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            write_stream(value, stream)
        os.replace(name, destination)
    finally:
        Path(name).unlink(missing_ok=True)
