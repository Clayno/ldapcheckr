from modules.module import Module
from lib.utils import translate_flags, convert_wi8_timestamp_to_timedelta

import asyncio
import re


class DomainInfos:
    def __init__(self, ldap_result):
        domain = ldap_result['attributes']
        self.machineAccountQuota = domain['ms-DS-MachineAccountQuota'][0].decode()
        self.DN = domain['distinguishedName']
        self.netbiosName = domain['dc'].upper()
        self.domainControllers = [
                re.search(r'CN=NTDS Settings,CN=([^,]*),', dc.decode()).groups()[0] 
                for dc in domain['msDS-IsDomainFor']
                ]

    def __repr__(self):
        to_return = f"""
DN: {self.DN}
NetbiosName: {self.netbiosName}
MachineAccountQuota: {self.machineAccountQuota}
DomainControllers:
    """
        to_return += '\n    '.join(self.domainControllers)
        #for attr, value in self.__dict__.items():
        #    to_return += f"\n\t{attr}: {value}"
        return to_return

class Domain(Module):

    async def _work(self):
        attributes = [
                'distinguishedName',
                'dc',
                'ms-DS-MachineAccountQuota',
                'msDS-IsDomainFor'
                ]
        
        # Iterator[(dict, Exception)]
        search = self.ldap_client.pagedsearch('(objectClass=domain)',
                attributes)
        async for domain, exc in search:
            domain_infos = DomainInfos(domain)
        self.data = [domain_infos]

    async def _result(self):
        return self.data[0]
