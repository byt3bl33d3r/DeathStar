import logging
import asyncio
import httpx
import json

log = logging.getLogger("deathstar.empire")

class EmpireLoginError(Exception):
    pass


class EmpireAgentNotFoundError(Exception):
    pass


class EmpireModuleExecutionTimeout(Exception):
    pass


class EmpireModuleExecutionError(Exception):
    pass


class EmpireObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, EmpireAgent):
            return obj.session_id
        if isinstance(obj, EmpireModule):
            return obj.name

        return json.JSONEncoder.default(self, obj)

json._default_encoder = EmpireObjectEncoder()

class EmpireApi:
    def __init__(self, api):
        self.api = api
        self.client = api.client


class EmpireObject(EmpireApi):
    def __init__(self, api, raw_object):
        super().__init__(api)
        self._raw = raw_object
        for k, v in raw_object.items():
            setattr(self, k.lower(), v)


class EmpireModule(EmpireObject):
    def __init__(self, api, raw_object):
        super().__init__(api, raw_object)
        del self.options["Agent"]

    async def execute(self, agent, timeout=10):
        return await self.api.modules.execute(self.name, agent, self.options, timeout)

    def __str__(self):
        return self.name


class EmpireCredential(EmpireObject):
    @property
    def pretty_username(self):
        return f"{self.domain}\\{self.username}"

    def __str__(self):
        return self.id


class EmpireAgent(EmpireObject):
    @property
    def domain(self):
        domain, user = self.username.split("\\")
        if domain != self.hostname and user != "SYSTEM":
            return domain.upper()
        return ""

    async def shell_nowait(self, cmd):
        return await self.api.agents.shell_nowait(cmd, self.session_id)

    async def shell(self, cmd, timeout=10):
        return await self.api.agents.shell(cmd, self.session_id, timeout)

    async def execute_nowait(self, module, options):
        return await self.api.modules.execute_nowait(module, self.session_id, options)

    async def execute(self, module, options={}, timeout=10):
        return await self.api.modules.execute(module, self.session_id, options, timeout)

    async def results(self, delete=False):
        return await self.api.agents.results(self.session_id, delete)

    async def kill(self):
        return await self.api.agents.kill(self.session_id)

    async def rename(self, new_name):
        r = await self.api.agents.rename(self.session_id, new_name)
        self.name = new_name
        return r

    async def task(self, task_id):
        return await self.api.agents.task(self.session_id, task_id)

    def __str__(self):
        return self.session_id


class EmpireUtils(EmpireApi):
    """
    Helper coroutines that try to take the quirkyness out of Empire's HTTP API
    """

    async def agent_has_staged(self, agent_data):
        """
        Empire API returns agents even when they haven't finished staging yet...
        """

        if (
            not agent_data["username"]
            or not agent_data["hostname"]
            or not agent_data["os_details"]
        ):
            return False
        return True

    async def poll_for_task_results(self, module, agent, timeout, task):
        """
        This will block until a specific task has a valid result
        """

        if "error" in task:
            raise EmpireModuleExecutionError(
                f"Error executing module/command '{module}': {task['error']}"
            )
        elif task["success"] == False:
            raise EmpireModuleExecutionError(
                f"Error executing module/command '{module}': {task['msg']}"
            )

        task_id = task["taskID"]

        n = 0
        while True:
            task = await self.api.agents.task(agent, task_id)

            if task["results"] != None and not task["results"].startswith(
                "Job started"
            ):
                log.debug(f"Agent {agent} returned results for task {task_id}")
                return task

            if timeout != -1:
                if n > timeout:
                    break
                n = +1

            await asyncio.sleep(1)

        raise EmpireModuleExecutionTimeout(
            f"Retrieving results for module/command '{module}' with taskID {task_id} exceeded timeout"
        )


class EmpireEvents(EmpireApi):
    async def all(self):
        r = await self.client.get("reporting")
        return r.json()["reporting"]

    async def agent(self, agent):
        r = await self.client.get(f"reporting/agent/{agent}")
        return r.json()["reporting"]

    async def type(self, type):
        r = await self.client.get(f"reporting/type/{type}")
        return r.json()["reporting"]

    async def message(self, msg):
        r = await self.client.get(f"reporting/msg/{msg}")
        return r.json()["reporting"]


class EmpireCredentials(EmpireApi):
    async def get(self):
        r = await self.client.get("creds")
        return [EmpireCredential(self.api, cred) for cred in r.json()["creds"]]


class EmpireModules(EmpireApi):
    def __init__(self, api):
        super().__init__(api)
        self._execute_lock = asyncio.Lock()

    async def get(self, module):
        r = await self.client.get(f"modules/{module}")
        return EmpireModule(self.api, r.json()["modules"][0])

    async def search(self, term):
        r = await self.client.post(f"modules/search", json={"term": term})
        return [EmpireModule(self.api, module) for module in r.json()["modules"]]

    async def execute_nowait(self, module, agent, options={}):
        """
        Ok, so you're probably wondering what in the kentucky fried fuck is the lock for the HTTP POST request all about.

        Empire wasn't designed to handle concurrent HTTP API requests as it interacts on the
        same underlying Python object(s) on each request (No locking or anything is present). 

        Meaning that if we make 2 (or more) concurrent API requests to execute the same module with diffrent options, 
        the requests will override each others options. Fun times 🤦‍♂️

        Since I have no intention of re-writing Empire, the quick fix is to add a mutex lock 
        in order to make this work as intended when we use this coroutine with asyncio.gather() calls.
        """

        async with self._execute_lock:
            r = await self.client.post(
                f"modules/{module}", json={"Agent": agent, **options}
            )
        return r.json()

    async def execute(self, module, agent, options={}, timeout=10):
        task = await self.execute_nowait(module, agent, options)
        return await self.api.utils.poll_for_task_results(module, agent, timeout, task)


class EmpireAgents(EmpireApi):
    def __init__(self, api):
        super().__init__(api)
        self._execute_lock = asyncio.Lock()

    async def get(self, agent=None):
        if agent:
            r = await self.client.get(f"agents/{agent}")
            agent_data = r.json()["agents"][0]
            if await self.api.utils.agent_has_staged(agent_data):
                return EmpireAgent(self.api, agent_data)
        else:
            r = await self.client.get("agents")
            return [
                EmpireAgent(self.api, result)
                for result in r.json()["agents"]
                if await self.api.utils.agent_has_staged(result)
            ]

    async def stale(self, delete=False):
        if delete:
            r = await self.client.delete("agents/stale")
        else:
            r = await self.client.get("agents/stale")
        return r.json()

    async def shell_nowait(self, cmd, agent):
        # I'm not sure if we need the lock here too but better safe then sorry
        async with self._execute_lock:
            r = await self.client.post(f"agents/{agent}/shell", json={"command": cmd})
        return r.json()

    async def shell(self, cmd, agent, timeout=10):
        task = await self.shell_nowait(cmd, agent)
        return await self.api.utils.poll_for_task_results(cmd, agent, timeout, task)

    async def remove(self, agent):
        r = await self.client.delete(f"agents/{agent}")
        return r.json()

    async def rename(self, agent, new_name):
        r = await self.client.post(f"agents/{agent}/rename", json={"newname": new_name})
        return r.json()

    async def results(self, agent, delete=False):
        if delete:
            r = await self.client.delete(f"agents/{agent}/results")
            return r.json()

        r = await self.client.get(f"agents/{agent}/results")
        return r.json()["results"][0]["AgentResults"]

    async def task(self, agent, task_id):
        r = await self.client.get(f"agents/{agent}/task/{task_id}")
        return r.json()

    async def kill(self, agent):
        r = await self.client.get(f"agents/{agent}/kill")
        return r.json()


class EmpireListeners(EmpireApi):
    async def get(self, listener=None):
        url = f"listeners/{listener}" if listener else "listeners"
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

    async def kill(self, listener):
        r = await self.client.delete(f"listeners/{listener}")
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
        self.utils = EmpireUtils(self)

    async def login(self, username, password):
        r = await self.client.post(
            "admin/login", json={"username": username, "password": password}
        )

        if r.status_code == 401:
            raise EmpireLoginError("Unable to login, credentials invalid")

        self.client.params = {"token": r.json()["token"]}

    async def close(self):
        await self.client.aclose()
