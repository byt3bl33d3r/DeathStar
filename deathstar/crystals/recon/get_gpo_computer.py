from deathstar.utils import posh_object_parser, beautify_json

async def crystallize(agent, gpo_guid):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_gpo_computer",
        options={
            "GUID": gpo_guid
        }
    )

    results = output["results"]
    parsed = posh_object_parser(results)
    log.debug(beautify_json(parsed))
    return parsed
