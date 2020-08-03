
async def crystallize(agent, computer_identity):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_gpo",
        options={
            "ComputerIdentity": computer_identity
        }
    )

    results = output["results"]
    log.debug(results)
    return results
