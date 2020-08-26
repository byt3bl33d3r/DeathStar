from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, computer_name):
    output = await agent.execute("powershell/credentials/invoke_internal_monologue")

    results = output["results"]
    return results
