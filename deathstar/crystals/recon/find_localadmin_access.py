from deathstar.utils import posh_object_parser, beautify_json

async def crystallize(agent, computer_name=""):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/find_localadmin_access",
        options={
            "ComputerName": computer_name
        }
    )

    results = output['results'].splitlines()
    log.debug(results)
    return results
