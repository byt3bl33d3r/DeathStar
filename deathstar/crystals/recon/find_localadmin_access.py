from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/find_localadmin_access",
        timeout=-1,
    )

    results = output["results"]
    parsed = results.split("\r\n")[:-3]
    log.debug(parsed)
    return parsed
