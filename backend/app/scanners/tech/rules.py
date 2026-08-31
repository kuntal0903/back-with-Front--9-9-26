"""
app/scanners/tech/rules.py

Defines fingerprint signatures and rules for matching technologies dynamically loaded from fingerprints.json.
"""

import json
from pathlib import Path
import re
from typing import NamedTuple, Pattern


class TechSignature(NamedTuple):
    """
    Structured rule set for fingerprinting a specific software, library, framework, or infrastructure.
    """

    name: str
    category: str
    headers: dict[str, Pattern[str]]  # Key is lowercase header name, value is regex
    html_patterns: list[Pattern[str]]
    meta_patterns: dict[str, Pattern[str]]  # Key is meta tag name, value is regex
    script_patterns: list[Pattern[str]]
    style_patterns: list[Pattern[str]]
    asset_patterns: list[Pattern[str]]
    cookies: list[Pattern[str]]
    dom_patterns: list[Pattern[str]]
    negative_indicators: list[Pattern[str]]
    version_parsers: list[Pattern[str]]
    confidence_default: str


def load_signatures_from_json(json_path: Path | None = None) -> list[TechSignature]:
    """
    Load tech fingerprints from JSON definition file and pre-compile regular expressions.
    """
    if json_path is None:
        json_path = Path(__file__).parent / "fingerprints.json"

    if not json_path.exists():
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    signatures = []
    for item in data:
        name = item.get("name", "")
        category = item.get("category", "")
        confidence_default = item.get("confidence_default", "medium")

        # Compile header regexes
        headers = {}
        for hk, hv in item.get("headers", {}).items():
            headers[hk.lower()] = re.compile(hv, re.IGNORECASE)

        # Compile html regexes
        html_patterns = [re.compile(p, re.IGNORECASE) for p in item.get("html_patterns", [])]

        # Compile meta regexes
        meta_patterns = {mk.lower(): re.compile(mv, re.IGNORECASE) for mk, mv in item.get("meta_patterns", {}).items()}

        # Compile script src regexes
        script_patterns = [re.compile(p, re.IGNORECASE) for p in item.get("script_patterns", [])]

        # Compile stylesheet href regexes
        style_patterns = [re.compile(p, re.IGNORECASE) for p in item.get("style_patterns", [])]

        # Compile asset path regexes
        asset_patterns = [re.compile(p, re.IGNORECASE) for p in item.get("asset_patterns", [])]

        # Compile cookie regexes
        cookies = [re.compile(p, re.IGNORECASE) for p in item.get("cookies", [])]

        # Compile dom regexes
        dom_patterns = [re.compile(p, re.IGNORECASE) for p in item.get("dom_patterns", [])]

        # Compile negative indicators
        negative_indicators = [re.compile(p, re.IGNORECASE) for p in item.get("negative_indicators", [])]

        # Compile version parsers
        version_parsers = [re.compile(p, re.IGNORECASE) for p in item.get("version_parsers", [])]

        signatures.append(
            TechSignature(
                name=name,
                category=category,
                headers=headers,
                html_patterns=html_patterns,
                meta_patterns=meta_patterns,
                script_patterns=script_patterns,
                style_patterns=style_patterns,
                asset_patterns=asset_patterns,
                cookies=cookies,
                dom_patterns=dom_patterns,
                negative_indicators=negative_indicators,
                version_parsers=version_parsers,
                confidence_default=confidence_default,
            )
        )

    return signatures


# Module-level compiled signatures
SIGNATURES: list[TechSignature] = load_signatures_from_json()
