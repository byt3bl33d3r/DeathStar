from deathstar.utils import posh_object_parser

async def crystallize(agent):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/user_hunter",
    )

    results = output['results']
    log.debug(results)
    return results
