import pytest
import os
from deathstar.empire import EmpireApiClient, EmpireModuleExecutionTimeout
from deathstar.utils import beautify_json

@pytest.mark.asyncio
@pytest.fixture
async def empire():
    empire = EmpireApiClient(host=os.environ["EMPIRE_HOST"])
    await empire.login("empireadmin", "Password123!")
    return empire

@pytest.mark.asyncio
@pytest.fixture
async def agent_name(empire):
    agents = await empire.agents.get()
    return agents[0]["name"]

@pytest.mark.asyncio
async def test_listeners(empire):
    r = await empire.listeners.create(name="DeathStar-Test", additional={"Port": 8989})
    r = await empire.listeners.get("DeathStar-Test")
    assert 'error' not in r

    await empire.listeners.kill("DeathStar-Test")

@pytest.mark.asyncio
async def test_agents(empire):
    agents = await empire.agents.get()
    assert len(agents) > 0

    name = agents[0]['name']
    agent = await empire.agents.get(name)
    assert agent

@pytest.mark.asyncio
async def test_modules(empire, agent_name):
    modules = await empire.modules.search("get_domain_sid")
    assert len(modules) > 0

    module = await empire.modules.get("powershell/management/get_domain_sid")
    assert module

    r = await empire.modules.execute(module["Name"], agent_name)
    print(beautify_json(r))
    assert r['results'] != None and not r['results'].startswith("Job started")

@pytest.mark.asyncio
async def test_agent_results(empire, agent_name):
    r = await empire.agents.results(agent_name)
    print(beautify_json(r))

@pytest.mark.asyncio
async def test_events(empire, agent_name):
    r = await empire.events.all()
    print(beautify_json(r))

    r = await empire.events.agent(agent_name)
    print(beautify_json(r))
