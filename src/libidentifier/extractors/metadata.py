"""Small metadata and framework hints."""

from __future__ import annotations

from .dex import ClassFeature
from ..models import FrameworkHint


def framework_hints_from_names(member_names: list[str], classes: list[ClassFeature]) -> list[FrameworkHint]:
    hints: list[FrameworkHint] = []
    lowered = {m.lower(): m for m in member_names}
    if "lib/armeabi-v7a/libflutter.so" in lowered or any(m.endswith("/libflutter.so") for m in lowered):
        hints.append(
            FrameworkHint(
                name="Flutter",
                evidence="libflutter.so",
                member=next(m for m in member_names if m.lower().endswith("/libflutter.so")),
                limitations=["Dart AOT package identification is not supported"],
            )
        )
    if any(c.descriptor.startswith("Lcom/facebook/react/") for c in classes):
        hints.append(
            FrameworkHint(
                name="React Native",
                evidence="com/facebook/react DEX classes",
                member=None,
                limitations=["JavaScript and Hermes package identification are not supported"],
            )
        )
    return sorted(hints, key=lambda h: (h.name, h.evidence))

