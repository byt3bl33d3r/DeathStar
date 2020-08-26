from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute("powershell/privesc/ask")

    results = output["results"]
    return results
