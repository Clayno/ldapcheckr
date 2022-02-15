#!/usr/bin/env python3

import asyncio
import json
import re
from termcolor import colored


UNINTERESTING_ATTRIBUTES = ["memberOf", "cn", "sAMAccountName", "name", "distinguishedName", "dNSHostName", "servicePrincipalName", "objectGUID", "sn", "objectClass", "displayName", "company", "logonHours", "objectSid", "sIDHistory", "userPrincipalName", "objectCategory", "mS-DS-ConsistencyGuid", "givenName"]

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

INTERESTING_PATTERNS_IN_INTERESTING_ATTRIBUTES = ["^(?=.*[A-Za-z])(?=.*\d)[^\s]{6,}$"]

def load_attributes():
    # https://gist.github.com/ropnop/ff2acb218b8dbbe8e1a5d5245abdfd8e
    with open("ADAttributes.json") as f:
        attributes = json.load(f)
        attributes = [ attr["Ldap-Display-Name"] for attr in attributes ]
    return attributes


async def get_creds(ldap_client):
    #blacklist = ['msExch', 'mDB']
    #attributes = load_attributes()
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
                    or any(re.match(pattern, v.lower()) for pattern in INTERESTING_PATTERNS) \
                    or any(re.match(pattern, v.lower()) for pattern in INTERESTING_PATTERNS_IN_INTERESTING_ATTRIBUTES if k in INTERESTING_ATTRIBUTES):
                if user['objectName'] not in results:
                    results[user['objectName']] = []
                results[user['objectName']].append(f"{str(k)}: {str(v)}")
    return results
