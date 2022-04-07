import traceback
import logging

logger = logging.getLogger()


class ModuleNotFinished(Exception):
    pass


class Module:
    def __init__(self, name, ldap_client):
        self.name = name
        self.ldap_client = ldap_client
        self.status = None

    async def run(self):
        try:
            self.status = "started"
            logger.info(f"We are starting {self.name} module")
            await self._work()
            logger.info(f"Ending {self.name} module")
            self.status = "terminated"
            return self
        except:
            self.status = "error"
            traceback.print_exc()
            raise Exception()

    async def _work(self):
        raise NotImplementedError("A Module class needs to implement a _work method.")

    def to_html(self):
        return ""

    def to_string(self):
        return ""

    async def get_result(self):
        if self.status != "started":
            return {
                "name": self.name,
                "status": self.status,
                "visual": {
                    "html": self.to_html(),
                    "string": self.to_string(),
                },
                "content": await self._result(),
            }
        else:
            raise ModuleNotFinished(
                "The Module is still working, the result isn't available"
            )

    async def _result(self):
        raise NotImplementedError("A Module class needs to implement a _return method.")
