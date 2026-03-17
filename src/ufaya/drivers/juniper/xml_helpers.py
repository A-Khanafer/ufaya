"""Low-level XML helpers for Junos configuration parsing.

All functions are namespace-agnostic—they strip ``{uri}`` prefixes so
callers can work with bare tag names regardless of whether the XML
carries a Junos namespace.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

# ---------------------------------------------------------------------------
# Junos XML namespace
# ---------------------------------------------------------------------------
JUNOS_NS = "http://xml.juniper.net/xnm/1.1/xnm"

# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

_DEVICE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]")


def sanitize_device_name(name: str) -> str:
    """Return a filesystem-safe device name."""
    return _DEVICE_NAME_RE.sub("_", name)


# ---------------------------------------------------------------------------
# Element lookup (namespace-agnostic)
# ---------------------------------------------------------------------------


def findall(element: ET.Element, path: str) -> list[ET.Element]:
    """Find direct children whose local tag equals *path*."""
    results: list[ET.Element] = []
    for child in element:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag == path:
            results.append(child)
    return results


def find(element: ET.Element, path: str) -> ET.Element | None:
    """Find the first direct child whose local tag equals *path*."""
    hits = findall(element, path)
    return hits[0] if hits else None


def find_recursive(element: ET.Element, tag: str) -> list[ET.Element]:
    """Recursively find all descendants matching *tag*."""
    results: list[ET.Element] = []
    for child in element.iter():
        local = child.tag
        if "}" in local:
            local = local.split("}", 1)[1]
        if local == tag:
            results.append(child)
    return results


def text(element: ET.Element | None) -> str | None:
    """Return the text content of *element*, or ``None``."""
    if element is None:
        return None
    return element.text


def elem_to_dict(elem: ET.Element) -> dict[str, Any]:
    """Recursively convert an XML element to a plain dict (for ``raw``)."""
    result: dict[str, Any] = {}
    for child in elem:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        child_dict = elem_to_dict(child)
        value: Any = child_dict if child_dict else (child.text or "")
        if tag in result:
            existing = result[tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[tag] = [existing, value]
        else:
            result[tag] = value
    return result
