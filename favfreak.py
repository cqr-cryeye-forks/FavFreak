#!/usr/bin/env python3
from multiprocessing.pool import ThreadPool
from time import time as timer
from urllib.request import urlopen
import argparse
import codecs
import errno
import mmh3
import os
import ssl
import sys
import json
from os import path


def load_fingerprints(filepath: str) -> dict:
    with open(filepath) as jsonFile:
        return json.load(jsonFile)


def fetch_url(url: str, ctx: ssl.SSLContext, a: dict) -> tuple[str, int | None, Exception | None]:
    try:
        response = urlopen(url, timeout=5, context=ctx)
        favicon = codecs.encode(response.read(), "base64")
        hash_value = mmh3.hash(favicon)
        a.setdefault(hash_value, []).append(url)
        return url, hash_value, None
    except Exception as e:
        return url, None, e


def main() -> tuple[dict, list[str]]:
    urls = [line.strip() + ("/favicon.ico" if line.strip()[-1] != "/" else "favicon.ico") for line in sys.stdin]
    a = {}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = timer()
    with ThreadPool(20) as pool:
        results = pool.imap_unordered(lambda url: fetch_url(url, ctx, a), urls)
        for url, hash_value, error in results:
            if error is None:
                print(f"Fetched {url[:-12]}")
            else:
                print(f"Not Fetched {url[:-12]}")

    for hash_value, url_list in a.items():
        print(f"Hash: {hash_value}")
        for url in url_list:
            print(f'^^^{url[:-12]}')

    return a, urls


def save_results(a: dict, fingerprint: dict, output: str | None, shodan: bool) -> None:
    results = {
        "fingerprints": {},
        "shodan_dorks": []
    }

    for hash_value, urls in a.items():
        results["fingerprints"][hash_value] = urls
        if shodan and hash_value != 0:
            results["shodan_dorks"].append(f"http.favicon.hash:{hash_value}")

    if output:
        output_fullpath = path.join(output, "results.json")
        os.makedirs(path.dirname(output_fullpath), exist_ok=True)
        with open(output_fullpath, "w") as jf:
            json.dump(results, jf, indent=2)

    for hash_value in a.keys():
        if str(hash_value) in fingerprint:
            print(f'{fingerprint[str(hash_value)]}: {hash_value}')

    if shodan:
        print("[Shodan Dorks]")
        for dork in results["shodan_dorks"]:
            print(f"[DORK] {dork}")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='FavFreak - a Favicon Hash based asset mapper')
        parser.add_argument('-o', '--output', help='Output file name')
        parser.add_argument('--shodan', help='Prints Shodan Dorks', action='store_true')
        args = parser.parse_args()

        if os.name == 'nt':
            os.system('cls')

        fingerprint = load_fingerprints("finger.json")
        a, urls = main()
        save_results(a, fingerprint, args.output, args.shodan)
    except KeyboardInterrupt:
        print("Keyboard Interrupt Encountered")
