import logging
import asyncio
import pkg_resources
import httpx
import random

log = logging.getLogger("deathstar.empire")


class EmpireLoginError(Exception):
    pass


class EmpireModuleExecutionTimeout(Exception):
    pass


class EmpireModuleExecutionError(Exception):
    pass


class EmpireEvents:
    def __init__(self, api):
        self.api = api
        self.client = api.client

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
    def __init__(self, api):
        self.api = api
        self.client = api.client

    async def get(self):
        r = await self.client.get("creds")
        return r.json()["creds"]


class EmpireModules:
    def __init__(self, api):
        self.api = api
        self.client = api.client
        # self.wrapped =

    async def get(self, name):
        r = await self.client.get(f"modules/{name}")
        return r.json()["modules"][0]

    async def search(self, term):
        r = await self.client.post(f"modules/search", json={"term": term})
        return r.json()["modules"]

    async def execute(self, name, agent, options={}, timeout=10):
        await asyncio.sleep(random.randint(1, 3))

        """
        Ok, so you're probably wondering what in the kentucky fried fuck is the above sleep statement all about.

        Empire wasn't designed to handle concurrent HTTP API requests as it interacts on the
        same underlying Python object(s) on each request (No locking, or anything). 

        Meaning that if we make 2 concurrent API requests to execute the same module with diffrent options, 
        the requests will override each others options. Fun times 🤦‍♂️

        Since I have no intention of re-writing Empire, the quick and horrendous fix is to add a small random delay between concurrent requests
        in order to make this work as intended if we use this coroutine with asyncio.gather() calls.
        """

        r = await self.client.post(f"modules/{name}", json={"Agent": agent, **options})
        if timeout == -1:
            return r.json()

        _json = r.json()
        if "error" in _json:
            log.error(f"Error executing module '{name}': {_json['error']}")
        elif _json["success"] == False:
            log.error(f"Error executing module '{name}': {_json['msg']}")

        task_id = _json["taskID"]

        n = 0
        while n <= timeout:
            task = self.api.agents.task(agent, task_id)

            if task["results"] != None and not task["results"].startswith(
                "Job started"
            ):
                log.debug(f"Agent {agent} returned results for task {task_id}")
                return task

            n = +1
            await asyncio.sleep(1)

        raise EmpireModuleExecutionTimeout(
            f"Retrieving results for module '{name}' with taskID {task_id} exceeded timeout"
        )


class EmpireAgents:
    def __init__(self, api):
        self.api = api
        self.client = api.client

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
        return r.json()["results"][0]["AgentResults"]

    async def task(self, name, task_id):
        r = await self.client.get(f"agents/{name}/task/{task_id}")
        return r.json()

    async def kill(self, name):
        r = await self.client.get(f"agents/{name}/kill")
        return r.json()


class EmpireListeners:
    def __init__(self, api):
        self.api = api
        self.client = api.client

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
