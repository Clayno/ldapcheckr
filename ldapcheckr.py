#!/usr/bin/env python3

import asyncio
import argparse
import json
from msldap.commons.factory import LDAPConnectionFactory

from lib.utils import import_module
from lib.logger import CheckrAdapter


MODULES = ["domain", "policy", "adidns", "creds"]


async def get_client(url):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
    log.info("[+] Connected to target")
    return ldap_client


async def main(url, args):
    ldap_client = await get_client(url)
    for corountine in asyncio.as_completed(
        [import_module(name, ldap_client).run() for name in MODULES]
    ):
        mod = await corountine
        result = await mod.get_result()
        log.title(f"{result.get('name').upper()}")
        if args.details:
            log.item(mod.data)
        else:
            log.item(result.get("content"))
        print("")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Diverse checks in LDAP repository.")
    parser.add_argument(
        "-d", "--domain", help="Domain to authenticate to", required=True
    )
    parser.add_argument(
        "-u", "--username", help="Username to authenticate with", required=True
    )
    parser.add_argument(
        "-s", "--secret", help="Secret to authenticate with. Can be a password, a hash or a file depending the authentication protocol chosen")
    parser.add_argument("-t", "--target", help="Target LDAP to request", required=True)
    parser.add_argument("--authproto", help="Authentication protocol to use", choices=("ntlm-password", "ntlm-nt", "kerberos-password", "kerberos-rc4", "kerberos-aes128", "kerberos-aes256", "kerberos-keytab", "kerberos-ccache", "kerberos-pfx", "kerberos-pem", "simple", "plain", "sicily", "none"), required=True)
    parser.add_argument("--dc", help="DC FQDN. Needed when using Kerberos")
    parser.add_argument("--protocol", help="Protocol to use", choices=("LDAP", "LDAPS", "GC", "GCS"), default="LDAP")
    enc = parser.add_mutually_exclusive_group()
    enc.add_argument("--hex", help="Provide the connection secret HEX encoded", action="store_true")
    enc.add_argument("--b64", help="Provide the connection secret B64 encoded", action="store_true")
    parser.add_argument("--details", action="store_true", help="Display details")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    log = CheckrAdapter(verbose=args.verbose)

    protocol = args.protocol
    authproto = args.authproto
    secret = args.secret
    if args.hex:
        authproto = f"{authproto}hex"
    elif args.b64:
        authproto = f"{authproto}b64"
    url = f"{protocol}+{authproto}://{args.domain}\\{args.username}:{secret}@{args.target}/"
    if "kerberos" in authproto:
        if not args.dc:
            log.error("When using Kerberos authentication, the --dc option (DC FQDN) is necessary")
            exit(1)
        url = f"{url}?dc={args.dc}"

    asyncio.run(main(url, args))
