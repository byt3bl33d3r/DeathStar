from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, group_name="Administrators", recurse=True):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_localgroup",
        options={"GroupName": group_name, "Recurse": str(recurse),},
    )

    results = output["results"]
    parsed = posh_object_parser(results)
    log.debug(beautify_json(parsed))
    return parsed
