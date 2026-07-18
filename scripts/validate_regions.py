#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGIONS_PATH = ROOT / "hub" / "regions.json"
COMPOSE_PATH = ROOT / "docker-compose.yml"
NGINX_PATH = ROOT / "hub" / "nginx.conf"


def main() -> int:
    regions = json.loads(REGIONS_PATH.read_text(encoding="utf-8"))
    slugs = [item["slug"] for item in regions]
    errors: list[str] = []

    required_keys = {"key", "slug", "uiPort", "proxyPort"}
    for index, item in enumerate(regions, start=1):
        missing_keys = required_keys - set(item)
        if missing_keys:
            errors.append(f"regions.json item {index} missing keys: {', '.join(sorted(missing_keys))}")
        if "slug" in item and not re.fullmatch(r"[a-z0-9-]+", str(item["slug"])):
            errors.append(f"regions.json item {index} has invalid slug: {item['slug']}")

    if len(slugs) != len(set(slugs)):
        errors.append("regions.json contains duplicate slugs")

    ui_ports = [item.get("uiPort") for item in regions]
    proxy_ports = [item.get("proxyPort") for item in regions]
    if len(ui_ports) != len(set(ui_ports)):
        errors.append("regions.json contains duplicate uiPort values")
    if len(proxy_ports) != len(set(proxy_ports)):
        errors.append("regions.json contains duplicate proxyPort values")

    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    nginx = NGINX_PATH.read_text(encoding="utf-8")

    dynamic_upstream = "nimbus-$region" in nginx

    for slug in slugs:
        if f"nimbus-{slug}:" not in compose and slug != "hub":
            errors.append(f"docker-compose.yml missing service nimbus-{slug}")
        if not dynamic_upstream and f"nimbus-{slug}" not in nginx:
            errors.append(f"hub/nginx.conf missing upstream nimbus-{slug}")

    matches = re.findall(r"\?<region>([^)]+)\)", nginx)
    if matches:
        for index, match in enumerate(matches, start=1):
            allowed = set(match.split("|"))
            missing = set(slugs) - allowed
            extra = allowed - set(slugs)
            if missing:
                errors.append(f"nginx region whitelist {index} missing: {', '.join(sorted(missing))}")
            if extra:
                errors.append(f"nginx region whitelist {index} has extra: {', '.join(sorted(extra))}")
    else:
        errors.append("hub/nginx.conf region whitelist not found")

    compose_ports = set(re.findall(r'"(\d+):\d+"', compose))
    for item in regions:
        slug = item.get("slug", "<unknown>")
        for key in ("uiPort", "proxyPort"):
            port = str(item.get(key, ""))
            if port and port not in compose_ports:
                errors.append(f"docker-compose.yml missing published {key} for {slug}: {port}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print(f"OK: {len(slugs)} regions validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
