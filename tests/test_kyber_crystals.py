import pytest
import logging
import asyncio
from deathstar.kybercrystals import KyberCrystals


class MockDeathStar:
    pass


@pytest.fixture
def kyber_crystals(empire):
    dt = MockDeathStar()
    dt.empire = empire

    k = KyberCrystals(dt)
    return k


@pytest.mark.asyncio
async def test_kyber_crystallization(kyber_crystals):
    assert kyber_crystals.get_domain_sid

    for crystal in kyber_crystals.loaded:
        assert isinstance(crystal.log, logging.Logger)
        assert isinstance(crystal.deathstar, MockDeathStar)


@pytest.mark.asyncio
async def test_crystal_focus(kyber_crystals, agent):
    sid = await kyber_crystals.get_domain_sid(agent)
    assert len(sid) > 0

    processes = await kyber_crystals.tasklist(agent)
    assert len(processes) > 0