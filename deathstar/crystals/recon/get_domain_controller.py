from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_domain_controller"
    )

    results = output["results"]
    parsed_obj = posh_object_parser(results)
    log.debug(beautify_json(parsed_obj))
    return parsed_obj
