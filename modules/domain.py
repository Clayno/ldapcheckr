import asyncio
import re
from lib.utils import translate_flags, convert_wi8_timestamp_to_timedelta


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
        to_return = f"""Domain Informations:
    DN: {self.DN}
    NetbiosName: {self.netbiosName}
    MachineAccountQuota: {self.machineAccountQuota}
    DomainControllers:
        """
        to_return += '\n\t'.join(self.domainControllers)
        for attr, value in self.__dict__.items():
            to_return += f"\t{attr}: {value}"
        return to_return

async def get_domain(ldap_client):
    attributes = [
            'distinguishedName',
            'dc',
            'ms-DS-MachineAccountQuota',
            'msDS-IsDomainFor'
            ]
    
    # Iterator[(dict, Exception)]
    search = ldap_client.pagedsearch('(objectClass=domain)',
            attributes)
    async for domain, exc in search:
        domain_infos = DomainInfos(domain)
    return [domain_infos]
