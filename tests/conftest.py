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
    yield empire


@pytest.mark.asyncio
@pytest.fixture
async def agents(empire):
    agents = await empire.agents.get()
    yield agents
