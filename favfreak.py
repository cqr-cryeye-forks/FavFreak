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
import re


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


def scan_vulnerabilities(domain: str) -> dict:
    try:
        result = subprocess.run(["nmap", "-sV", domain], capture_output=True, text=True)
        return {"domain": domain, "nmap_output": result.stdout}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def parse_nmap_output(nmap_output: str) -> Dict[str, Any]:
    results = {
        "domain": "",
        "ip_address": "",
        "host_status": "",
        "ports": [],
        "service_info": {}
    }

    # Extract domain and IP address
    domain_ip_pattern = re.compile(r'Nmap scan report for (.+) \(([\d\.]+)\)')
    domain_ip_match = domain_ip_pattern.search(nmap_output)
    if domain_ip_match:
        results["domain"] = domain_ip_match.group(1)
        results["ip_address"] = domain_ip_match.group(2)

    # Extract host status
    host_status_pattern = re.compile(r'Host is (.+) \(([\d\.]+)s latency\)')
    host_status_match = host_status_pattern.search(nmap_output)
    if host_status_match:
        results["host_status"] = host_status_match.group(1)

    # Extract ports and services
    ports_pattern = re.compile(r'(\d+/tcp)\s+(\w+)\s+(\w+)\s+(.+)')
    for port_match in ports_pattern.finditer(nmap_output):
        port_info = {
            "port": port_match.group(1),
            "state": port_match.group(2),
            "service": port_match.group(3),
            "version": port_match.group(4)
        }
        results["ports"].append(port_info)

    # Extract service info
    service_info_pattern = re.compile(r'Service Info: (.+)')
    service_info_match = service_info_pattern.search(nmap_output)
    if service_info_match:
        for info in service_info_match.group(1).split(";"):
            key_value = info.split(":", 1)  # Split only on the first colon
            if len(key_value) == 2:
                key, value = key_value
                results["service_info"][key.strip()] = value.strip()

    return results


def main(target_url: str, fingerprint: Dict[str, Any], output: pathlib.Path) -> None:
    # Ensure URL starts with http:// or https://
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # Ensure URL ends with "/favicon.ico"
    favicon_url = target_url.rstrip("/") + "/favicon.ico"
    domain = target_url.split("//")[-1].split("/")[0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Fetch favicon and calculate hash
    url, hash_value, error = fetch_favicon(favicon_url, ctx)

    results = {
        "target": target_url,
        "hash": hash_value,
        "fingerprint": fingerprint.get(str(hash_value), "Unknown"),
        "vulnerability_scan": {},
        "error": str(error) if error else None
    }

    if error is None:
        # Perform vulnerability scan if fetching favicon was successful
        scan_result = scan_vulnerabilities(domain)
        if "nmap_output" in scan_result:
            results["vulnerability_scan"] = parse_nmap_output(scan_result["nmap_output"])
        else:
            results["vulnerability_scan"] = scan_result

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
