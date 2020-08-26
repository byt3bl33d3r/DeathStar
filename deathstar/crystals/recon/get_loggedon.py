from deathstar.utils import posh_table_parser, beautify_json


async def crystallize(agent, computer_name="localhost"):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_loggedon",
        options={"ComputerName": computer_name},
    )

    results = output["results"]
    parsed = posh_table_parser(results)
    filtered = list(filter(lambda s: not s["username"].endswith("$"), parsed))
    log.debug(beautify_json(filtered))
    return filtered
