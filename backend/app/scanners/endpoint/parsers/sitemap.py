"""
app/scanners/endpoint/parsers/sitemap.py

Parses sitemap.xml and sitemap index XML files to extract referenced URLs.
"""

import xml.etree.ElementTree as ET
from urllib.parse import urljoin


def parse_sitemap_xml(base_url: str, xml_content: str, max_urls: int = 500) -> tuple[list[str], list[str]]:
    """
    Parse sitemap XML content safely.
    
    Args:
        base_url: The URL of the sitemap file.
        xml_content: Raw XML payload string.
        max_urls: Cap on max extracted URLs to prevent unbounded processing.
        
    Returns:
        tuple[list[str], list[str]]:
            - url_locations: List of extracted page/resource URLs.
            - child_sitemaps: List of nested sitemap index URLs.
    """
    url_locations = []
    child_sitemaps = []

    try:
        root = ET.fromstring(xml_content)
        # Handle XML namespaces dynamically
        # Element tags usually look like '{http://www.sitemaps.org/schemas/sitemap/0.9}urlset'
        tag_name = root.tag.split("}")[-1] if "}" in root.tag else root.tag

        if tag_name == "urlset":
            for child in root:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "url":
                    for elem in child:
                        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if elem_tag == "loc" and elem.text:
                            loc_url = elem.text.strip()
                            if loc_url:
                                url_locations.append(urljoin(base_url, loc_url))
                                if len(url_locations) >= max_urls:
                                    break
                if len(url_locations) >= max_urls:
                    break

        elif tag_name == "sitemapindex":
            for child in root:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "sitemap":
                    for elem in child:
                        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if elem_tag == "loc" and elem.text:
                            sitemap_url = elem.text.strip()
                            if sitemap_url:
                                child_sitemaps.append(urljoin(base_url, sitemap_url))

    except Exception:
        # Ignore XML syntax errors gracefully
        pass

    # Deduplicate lists
    deduped_urls = list(dict.fromkeys(url_locations))
    deduped_sitemaps = list(dict.fromkeys(child_sitemaps))

    return deduped_urls, deduped_sitemaps
