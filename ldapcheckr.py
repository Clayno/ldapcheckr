#!/usr/bin/env python3

import asyncio
import argparse
import json
from msldap.commons.url import MSLDAPURLDecoder

from modules.policy import get_policies
from modules.creds import get_creds
from modules.domain import get_domain

async def get_client(url):
    conn_url = MSLDAPURLDecoder(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
    return ldap_client


async def main(url):
    ldap_client = await get_client(url)
    print('########################## DOMAIN INFOS #########################')
    infos = await get_domain(ldap_client)
    print(infos[0])
    print('########################## DOMAIN POLICIES #########################')
    passpols = await get_policies(ldap_client)
    for passpol in passpols:
        print(passpol)
        print()
    print('########################## CREDS IN DESCRIPTION #########################')
    creds = await get_creds(ldap_client) 
    print(json.dumps(creds, sort_keys=True, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Check for credz in LDAP fields")
    parser.add_argument("-d", "--domain", help="Domain to authenticate to", required=True)
    parser.add_argument("-u", "--username", help="Username to authenticate with", required=True)
    parser.add_argument("-p", "--password", help="Password to authenticate with", required=True)
    parser.add_argument("-t", "--target", help="Target LDAP to request", required=True)
    args = parser.parse_args()
    url = f"ldap+ntlm-password://{args.domain}\\{args.username}:{args.password}@{args.target}"
    asyncio.run(main(url))

