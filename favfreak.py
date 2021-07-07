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

fingerprint = {}
with open("finger.json") as jsonFile:
    fingerprint = json.load(jsonFile)
    jsonFile.close()


def main():
    urls = []
    c = 0
    a = {}
    for line in sys.stdin:
        if line.strip()[-1] == "/":
            urls.append(line.strip() + "favicon.ico")
        else:
            urls.append(line.strip() + "/favicon.ico")

    def fetch_url(url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            response = urlopen(url, timeout=5, context=ctx)
            favicon = codecs.encode(response.read(), "base64")
            hash = mmh3.hash(favicon)
            key = hash
            a.setdefault(key, [])
            a[key].append(url)

            return url, hash, None
        except Exception as e:
            return url, None, e

    start = timer()
    results = ThreadPool(20).imap_unordered(fetch_url, urls)
    for url, hash, error in results:
        if error is None:
            print("Fetched %s" % str(url[:-12]))
        else:
            print("Not Fetched %r " % (url[:-12]))
    # print("\n")
    # print("-------------------------------------------------------------------")
    # print("Favicon Hash Results")
    for i, j in a.items():
        # if len(j) > 1:
        #     print("Hash + str(i))
        #     for k in j:
        #         print("     " + k[:-12])
        # else:
        print("Hash: " + str(i))
        for k in j:
            print(k[:-12])

    return a, urls


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='FavFreak - a Favicon Hash based asset mapper')
        parser.add_argument('-o', '--output', help='Output file name')
        parser.add_argument('--shodan', help='Prints Shodan Dorks', action='store_true')
        args = parser.parse_args()
        if os.name == 'nt':
            os.system('cls')

        a, urls = main()

        # print("FingerPrint Based Detection Results")
        for i in a.keys():
            if str(i) in fingerprint.keys():
                # print(fingerprint[i] + str(i) + " - count : " + str(len(a[i])))
                print(f'{fingerprint[str(i)]}: {i}')
                # print('\n'.join(a[i][:-12]))
                # if len(a[i]) > 0:
                    # for k in a[i]:
                    #     print("     " + k[:-12])

        # print("\n")
        if args.shodan:
            print("[Shodan Dorks]")
            for i in a.keys():
                if i != 0:
                    print("[DORK] http.favicon.hash:" + str(i))

        if args.output:
            for i in a.keys():
                filename = args.output + "/" + str(i) + ".txt"
                if path.exists(filename):
                    os.remove(filename)
                if not os.path.exists(os.path.dirname(filename)):
                    try:
                        os.makedirs(os.path.dirname(filename))
                    except OSError as exc:
                        if exc.errno != errno.EEXIST:
                            raise

                with open(filename, "a") as f:
                    f.write('\n'.join(a[i]))
                    f.write("\n")
        # print("Summary")
        # print("Hash")
        # for i in a.keys():
        #     print(f"{len(a[i])}: {i}")
    except KeyboardInterrupt:
        print("KeyBoard Interrupt Encountered")
