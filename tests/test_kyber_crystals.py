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
    output = await kyber_crystals.get_domain_sid(agent)
    assert len(output) > 0

    sid = output[0]

    output, output2 = await asyncio.gather(
        *[
            kyber_crystals.get_group_member(agent, sid + "-512"),
            kyber_crystals.get_group_member(agent, sid + "-519"),
        ]
    )

    print(output)
    print(output2)
