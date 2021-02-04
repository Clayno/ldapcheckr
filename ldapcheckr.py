import asyncio
import json
import math
import passwordmeter
import argparse
from termcolor import colored
from msldap.commons.url import MSLDAPURLDecoder


INTERESTING_ATTRIBUTES = {"comment": False,
        "description": False,
        "info": False,
        "UserPassword": True,
        "UnixUserPassword": True,
        "unicodePwd": True,
        "msSFU30Password": True,
        "ms-Mcs-AdmPwd": True}

INTERESTING_ATTRIBUTES_LIST = [ k for k in INTERESTING_ATTRIBUTES.keys() ]

INTERESTING_KEYWORDS = ["mdp",
        "mot de passe",
        "pwd",
        "pw",
        "password",
        "passwd"
        ]

PASSWORDMETER_STRENGTH = 0.45
ENTROPY_THRESHOLD = 3.1

def load_attributes():
    # https://gist.github.com/ropnop/ff2acb218b8dbbe8e1a5d5245abdfd8e
    with open("ADAttributes.json") as f:
        attributes = json.load(f)
        attributes = [ attr["Ldap-Display-Name"] for attr in attributes ]
    return attributes

def entropy(string):
    "Calculates the Shannon entropy of a string"
    # get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    # calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def analyze(string):
    return False
    '''
    words = string.split()
    for word in words:
        strength, _ = passwordmeter.test(word)
        if strength > PASSWORDMETER_STRENGTH:
            return True
        if len(words) == 1 and entropy(word) > ENTROPY_THRESHOLD:
            return True
    return False
    '''

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
        interesting = False
        output = f"{user['objectName']}\n"
        for k,v in user['attributes'].items():
        #    if k not in attributes and not any(b in k for b in blacklist):
        #        print(f"{str(k)}: {str(v)}")
            if k in INTERESTING_ATTRIBUTES_LIST: 
                #interesting = True
                if isinstance(v, list):
                    v = ''.join(subvalue.decode() for subvalue in v)
                if any(keyword in v.lower() for keyword in INTERESTING_KEYWORDS) \
                        or INTERESTING_ATTRIBUTES[k] \
                        or analyze(v):
                    output += colored(f"    {str(k)}: {str(v)}\n", "yellow", attrs=['bold'])
                    if user['objectName'] not in results:
                        results[user['objectName']] = []
                    results[user['objectName']].append(f"{str(k)}: {str(v)}")
                else:
                    output += f"    {str(k)}: {str(v)}\n"
        if interesting:
            print(output)
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

