import logging
import asyncio
import httpx

log = logging.getLogger("deathstar.empire")


class EmpireLoginError(Exception):
    pass

class EmpireModuleExecutionTimeout(Exception):
    pass

class EmpireEvents:
    def __init__(self, empire_api):
        self.empire_api = empire_api
        self.client = empire_api.client

    async def all(self):
        r = await self.client.get("reporting")
        return r.json()["reporting"]

    async def agent(self, name):
        r = await self.client.get(f"reporting/agent/{name}")
        return r.json()["reporting"]

    async def type(self, type):
        r = await self.client.get(f"reporting/type/{type}")
        return r.json()["reporting"]

    async def message(self, msg):
        r = await self.client.get(f"reporting/msg/{msg}")
        return r.json()["reporting"]


class EmpireCredentials:
    def __init__(self, empire_api):
        self.empire_api = empire_api
        self.client = empire_api.client

    async def get(self):
        r = await self.client.get("creds")
        return r.json()["creds"]


class EmpireModules:
    def __init__(self, empire_api):
        self.empire_api = empire_api
        self.client = empire_api.client

    async def get(self, name):
        r = await self.client.get(f"modules/{name}")
        return r.json()["modules"][0]

    async def search(self, term):
        r = await self.client.post(f"modules/search", json={"term": term})
        return r.json()["modules"]

    async def execute(self, name, agent, options={}, timeout=10):
        r = await self.client.post(f"modules/{name}", json={"Agent": agent, **options})
        if timeout == -1:
            return r.json()

        task_id = r.json()['taskID']

        n = 0
        while n <= timeout:
            for task in filter(
                    lambda r: r['taskID'] == task_id,
                    await self.empire_api.agents.results(agent)
                ):

                if task['results'] != None and not task['results'].startswith("Job started"):
                    return task

            n =+ 1
            await asyncio.sleep(1)

        raise EmpireModuleExecutionTimeout(f"Retrieving results for module '{name}' with taskID {task_id} exceeded timeout")


class EmpireAgents:
    def __init__(self, empire_api):
        self.empire_api = empire_api
        self.client = empire_api.client

    async def get(self, name=None):
        url = f"agents/{name}" if name else "agents"
        r = await self.client.get(url)
        return r.json()["agents"][0] if name else r.json()["agents"]

    async def stale(self, delete=False):
        if delete:
            r = await self.client.delete("agents/stale")
        else:
            r = await self.client.get("agents/stale")
        return r.json()

    async def shell(self, name, cmd):
        r = await self.client.post(f"agents/{name}/shell", json={"command": cmd})
        return r.json()

    async def remove(self, name):
        r = await self.client.delete(f"agents/{name}")
        return r.json()

    async def rename(self, name, new_name):
        r = await self.client.post(f"agents/{name}", json={"newname": new_name})
        return r.json()

    async def results(self, name, delete=False):
        if delete:
            r = await self.client.delete(f"agents/{name}/results")
            return r.json()

        r = await self.client.get(f"agents/{name}/results")
        return r.json()['results'][0]['AgentResults']

    async def kill(self, name):
        r = await self.client.get(f"agents/{name}/kill")
        return r.json()


class EmpireListeners:
    def __init__(self, empire_api):
        self.empire_api = empire_api
        self.client = empire_api.client

    async def get(self, name=None):
        url = f"listeners/{name}" if name else "listeners"

        r = await self.client.get(url)
        return r.json()

    async def options(self, listener_type="http"):
        r = await self.client.get(f"listeners/options/{listener_type}")
        return r.json()

    async def create(self, listener_type="http", name="DeathStar", additional={}):
        r = await self.client.post(
            f"listeners/{listener_type}", json={"Name": name, **additional}
        )

        return r.json()["success"]

    async def kill(self, name):
        r = await self.client.delete(f"listeners/{name}")
        return r.json()


class EmpireApiClient:
    def __init__(self, host="localhost", port="1337"):
        self.client = httpx.AsyncClient(
            base_url=f"https://{host}:{port}/api/", verify=False
        )
        self.credentials = EmpireCredentials(self)
        self.listeners = EmpireListeners(self)
        self.agents = EmpireAgents(self)
        self.modules = EmpireModules(self)
        self.events = EmpireEvents(self)

    async def login(self, username, password):
        r = await self.client.post(
            "admin/login", json={"username": username, "password": password}
        )

        if r.status_code == 401:
            raise EmpireLoginError("Unable to login, credentials invalid")

        self.client.params = {"token": r.json()["token"]}
