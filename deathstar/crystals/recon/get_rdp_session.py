from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, computer_name="localhost"):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_rdp_session",
        options={"ComputerName": computer_name},
    )

    results = output["results"]
    parsed = posh_object_parser(results)
    filtered = list(
        filter(lambda s: s["sessionname"] not in ["Console", "Services"], parsed)
    )

    log.debug(beautify_json(filtered))
    return filtered
