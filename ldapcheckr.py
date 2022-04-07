#!/usr/bin/env python3

import asyncio
import argparse
import json
from msldap.commons.url import MSLDAPURLDecoder

from lib.utils import import_module
from lib.logger import CheckrAdapter


MODULES = ["domain", "policy", "adidns", "creds"]

async def get_client(url):
    conn_url = MSLDAPURLDecoder(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
    log.info("[+] Connected to target")
    return ldap_client


async def main(url, args):
    ldap_client = await get_client(url)
    for corountine in asyncio.as_completed([import_module(name, ldap_client).run() for name in MODULES]):
        mod = await corountine
        result = await mod.get_result()
        log.title(f"{result.get('name').upper()}")
        if args.details:
            log.item(mod.data)
        else:
            log.item(result.get("content"))
        log.info('')

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Check for credz in LDAP fields")
    parser.add_argument("-d", "--domain", help="Domain to authenticate to", required=True)
    parser.add_argument("-u", "--username", help="Username to authenticate with", required=True)
    parser.add_argument("-p", "--password", help="Password to authenticate with", required=True)
    parser.add_argument("-t", "--target", help="Target LDAP to request", required=True)
    parser.add_argument("--details", action="store_true", help="Display details")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    log = CheckrAdapter(verbose=args.verbose)
    url = f"ldap+ntlm-password://{args.domain}\\{args.username}:{args.password}@{args.target}"
    asyncio.run(main(url, args))

