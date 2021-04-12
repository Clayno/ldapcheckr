import asyncio
import json
import argparse
import re
from termcolor import colored
from msldap.commons.url import MSLDAPURLDecoder


UNINTERESTING_ATTRIBUTES = ["memberOf", "cn", "sAMAccountName", "name", "distinguishedName", "dNSHostName", "servicePrincipalName"]

INTERESTING_ATTRIBUTES = {"comment": False,
        "description": False,
        "info": False,
        "UserPassword": True,
        "userPassword": True,
        "UnixUserPassword": True,
        "unixUserPassword": True,
        "unicodePwd": True,
        "msSFU30Password": True,
        "ms-Mcs-AdmPwd": True}

INTERESTING_ATTRIBUTES_LIST = [ k for k in INTERESTING_ATTRIBUTES.keys() ]

INTERESTING_KEYWORDS = ["mdp",
        "mot de passe",
        "password",
        "passwd"
        ]

INTERESTING_PATTERNS = ["[^\w]pwd[^\w]",
    "[^\w]pw[^\w]",
    "[^\w]mdp[^\w]"
    ]

def load_attributes():
    # https://gist.github.com/ropnop/ff2acb218b8dbbe8e1a5d5245abdfd8e
    with open("ADAttributes.json") as f:
        attributes = json.load(f)
        attributes = [ attr["Ldap-Display-Name"] for attr in attributes ]
    return attributes


async def client(url):
    #blacklist = ['msExch', 'mDB']
    #attributes = load_attributes()
    conn_url = MSLDAPURLDecoder(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
   
    results = {}
    users = ldap_client.pagedsearch('(objectClass=user)', ['*'])
    async for user in users:
        user = user[0]
        output = f"{user['objectName']}\n"
        for k,v in user['attributes'].items():
            if k in UNINTERESTING_ATTRIBUTES:
                continue
            if isinstance(v, list):
                try:
                    v = ''.join(subvalue.decode() if isinstance(subvalue, type(b'')) else subvalue for subvalue in v)
                except:
                    v = ''
            if not isinstance(v, str):
                continue
            if any(keyword in v.lower() for keyword in INTERESTING_KEYWORDS) \
                    or (k in INTERESTING_ATTRIBUTES and INTERESTING_ATTRIBUTES[k]) \
                    or any(re.match(pattern, v.lower()) for pattern in INTERESTING_PATTERNS):
                if user['objectName'] not in results:
                    results[user['objectName']] = []
                results[user['objectName']].append(f"{str(k)}: {str(v)}")
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Check for credz in LDAP fields")
    parser.add_argument("-d", "--domain", help="Domain to authenticate to", required=True)
    parser.add_argument("-u", "--username", help="Username to authenticate with", required=True)
    parser.add_argument("-p", "--password", help="Password to authenticate with", required=True)
    parser.add_argument("-t", "--target", help="Target LDAP to request", required=True)
    args = parser.parse_args()
    url = f"ldap+ntlm-password://{args.domain}\\{args.username}:{args.password}@{args.target}"
    print(url)
    results = asyncio.run(client(url))
    print(json.dumps(results, sort_keys=True, indent=4))

