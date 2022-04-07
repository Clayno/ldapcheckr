from modules.module import Module

import socket
from struct import unpack, pack
import datetime
from builtins import str



class Adidns(Module):
    async def _work(self):
        nodes = []
        attributes = ['dnsRecord','dNSTombstoned','name']
        # Searching for wpad and '*' nodes
        dns_nodes = self.ldap_client.pagedsearch(
                '(&(objectClass=dnsNode)(|(name=\*)(name=wpad)))',
                attributes)
        async for node, exc in dns_nodes:
            nodes.append(node)
        self.data = nodes

    async def _result(self):

        if not self.data:
            return "No records found for wpad and '*'..."
        return "".join("\n", self.data)
