from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, computer_name="localhost"):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_session",
        options={"ComputerName": computer_name},
    )

    results = output["results"]
    parsed = posh_object_parser(results)
    log.debug(beautify_json(parsed))
    return parsed
