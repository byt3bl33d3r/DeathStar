import pytest
import logging
import os
from deathstar.empire import EmpireApiClient, EmpireModuleExecutionTimeout

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s - %(message)s"))

log = logging.getLogger("deathstar")
log.setLevel(logging.DEBUG)
log.addHandler(handler)


@pytest.mark.asyncio
@pytest.fixture
async def empire():
    empire = EmpireApiClient(host=os.environ["EMPIRE_HOST"])
    await empire.login("empireadmin", "Password123!")
    return empire


@pytest.mark.asyncio
@pytest.fixture
async def agent(empire):
    agents = await empire.agents.get()
    return agents[0]["name"]
