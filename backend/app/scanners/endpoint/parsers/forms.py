"""
app/scanners/endpoint/parsers/forms.py

Parses HTML forms to extract form action endpoints, HTTP methods, and input parameter structures.
"""

import re
from typing import NamedTuple
from urllib.parse import urljoin

_FORM_TAG_PATTERN = re.compile(r"<form\s+([^>]*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_ATTR_PATTERN = re.compile(r"\baction\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_METHOD_ATTR_PATTERN = re.compile(r"\bmethod\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_INPUT_TAG_PATTERN = re.compile(r"<input\s+([^>]*?)>", re.IGNORECASE)
_NAME_ATTR_PATTERN = re.compile(r"\bname\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_TYPE_ATTR_PATTERN = re.compile(r"\btype\s*=\s*[\"'](.*?)[\"']", re.IGNORECASE)
_SELECT_TAG_PATTERN = re.compile(r"<select\s+([^>]*?)>", re.IGNORECASE)
_TEXTAREA_TAG_PATTERN = re.compile(r"<textarea\s+([^>]*?)>", re.IGNORECASE)


class FormDetails(NamedTuple):
    action_url: str
    method: str
    inputs: list[dict[str, str]]  # list of {"name": name, "type": type}
    param_names: list[str]


def parse_html_forms(base_url: str, html_body: str) -> list[FormDetails]:
    """
    Scrape all HTML <form> elements and extract their action target, method, and parameters.
    
    Args:
        base_url: The page source URL.
        html_body: Raw HTML content string.
        
    Returns:
        list[FormDetails]: Parsed forms details.
    """
    forms = []

    matches = _FORM_TAG_PATTERN.finditer(html_body)

    for match in matches:
        attrs = match.group(1)
        body = match.group(2)

        # Extract action URL
        action_match = _ACTION_ATTR_PATTERN.search(attrs)
        action_val = action_match.group(1).strip() if action_match else ""
        action_url = urljoin(base_url, action_val) if action_val else base_url

        # Extract HTTP method
        method_match = _METHOD_ATTR_PATTERN.search(attrs)
        method = method_match.group(1).strip().upper() if method_match else "GET"

        inputs = []
        param_names = []

        # Parse <input> tags
        for inp_match in _INPUT_TAG_PATTERN.finditer(body):
            inp_attrs = inp_match.group(1)
            n_match = _NAME_ATTR_PATTERN.search(inp_attrs)
            t_match = _TYPE_ATTR_PATTERN.search(inp_attrs)
            if n_match:
                name = n_match.group(1).strip()
                inp_type = t_match.group(1).strip().lower() if t_match else "text"
                if name:
                    inputs.append({"name": name, "type": inp_type})
                    param_names.append(name)

        # Parse <select> tags
        for sel_match in _SELECT_TAG_PATTERN.finditer(body):
            sel_attrs = sel_match.group(1)
            n_match = _NAME_ATTR_PATTERN.search(sel_attrs)
            if n_match:
                name = n_match.group(1).strip()
                if name:
                    inputs.append({"name": name, "type": "select"})
                    param_names.append(name)

        # Parse <textarea> tags
        for ta_match in _TEXTAREA_TAG_PATTERN.finditer(body):
            ta_attrs = ta_match.group(1)
            n_match = _NAME_ATTR_PATTERN.search(ta_attrs)
            if n_match:
                name = n_match.group(1).strip()
                if name:
                    inputs.append({"name": name, "type": "textarea"})
                    param_names.append(name)

        deduped_params = list(dict.fromkeys(param_names))

        forms.append(
            FormDetails(
                action_url=action_url,
                method=method,
                inputs=inputs,
                param_names=deduped_params,
            )
        )

    return forms
