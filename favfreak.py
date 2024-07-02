#!/usr/bin/env python3
import pathlib
from urllib.request import urlopen
import argparse
import codecs
import mmh3
import ssl
import json
import os
import subprocess
from typing import Dict, Any, Tuple, Final


def load_fingerprints(filepath: str) -> Dict[str, Any]:
    with open(filepath) as jsonFile:
        return json.load(jsonFile)


def fetch_favicon(url: str, ctx: ssl.SSLContext) -> Tuple[str, int | None, Exception | None]:
    try:
        response = urlopen(url, timeout=5, context=ctx)
        favicon = codecs.encode(response.read(), "base64")
        hash_value = mmh3.hash(favicon)
        return url, hash_value, None
    except Exception as e:
        return url, None, e


def scan_vulnerabilities(url: str) -> dict:
    try:
        result = subprocess.run(["nmap", "-sV", url], capture_output=True, text=True)
        return {"url": url, "nmap_output": result.stdout}
    except Exception as e:
        return {"url": url, "error": str(e)}


def main(target_url: str, fingerprint: Dict[str, Any], output: pathlib.Path) -> None:
    # Ensure URL ends with "/favicon.ico"
    if not target_url.endswith("/favicon.ico"):
        target_url = target_url.rstrip("/") + "/favicon.ico"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Fetch favicon and calculate hash
    url, hash_value, error = fetch_favicon(target_url, ctx)

    results = {
        "target": target_url,
        "hash": hash_value,
        "fingerprint": fingerprint.get(str(hash_value), "Unknown"),
        "vulnerability_scan": {}
    }

    if error is None:
        # Perform vulnerability scan if fetching favicon was successful
        scan_result = scan_vulnerabilities(target_url.rstrip("/favicon.ico"))
        results["vulnerability_scan"] = scan_result
    else:
        results["error"] = str(error)

    with open(output, "w") as jf:
        json.dump(results, jf, indent=2)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
            description='FavFreak - a Favicon Hash based asset mapper and vulnerability scanner')
        parser.add_argument('--target', required=True, help='Target URL or domain to scan')
        parser.add_argument('--output', required=True, help='Output JSON file')
        args = parser.parse_args()

        if os.name == 'nt':
            os.system('cls')

        MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
        OUTPUT: Final[pathlib.Path] = MAIN_DIR / args.output

        fingerprint = load_fingerprints("finger.json")
        main(args.target, fingerprint, OUTPUT)
    except KeyboardInterrupt:
        print("Keyboard Interrupt Encountered")
