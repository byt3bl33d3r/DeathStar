from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, group_sid, recurse=True):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_group_member",
        options={
            "Identity": group_sid,
            "Recurse": str(recurse).lower(),  # Empire doesn't do any type checking or type conversions...
        },
    )

    results = output["results"]
    parsed_obj = posh_object_parser(results)
    log.debug(beautify_json(parsed_obj))
    return parsed_obj
