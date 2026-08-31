"""
app/scanners/endpoint/parsers/robots.py

Parses robots.txt text to discover referenced paths, allow/disallow directives, and sitemap locations.
"""

from urllib.parse import urljoin


def parse_robots_txt(base_url: str, content: str) -> tuple[list[str], list[str]]:
    """
    Parse robots.txt file content.
    
    Args:
        base_url: Originating URL of robots.txt.
        content: Raw text of robots.txt.
        
    Returns:
        tuple[list[str], list[str]]:
            - discovered_urls: Absolute paths from Allow / Disallow rules.
            - sitemap_urls: Absolute URLs of referenced sitemaps.
    """
    discovered_urls = []
    sitemap_urls = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        directive, _, val = line.partition(":")
        directive = directive.strip().lower()
        val = val.strip()

        if not val:
            continue

        if directive in ("disallow", "allow"):
            # Strip wildcard trailing parameters for base endpoint identity
            clean_path = val.rstrip("*")
            if clean_path:
                abs_url = urljoin(base_url, clean_path)
                discovered_urls.append(abs_url)

        elif directive == "sitemap":
            abs_sitemap = urljoin(base_url, val)
            sitemap_urls.append(abs_sitemap)

    # Deduplicate preserving order
    deduped_paths = list(dict.fromkeys(discovered_urls))
    deduped_sitemaps = list(dict.fromkeys(sitemap_urls))

    return deduped_paths, deduped_sitemaps
