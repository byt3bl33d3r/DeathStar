async def crystallize(
    agent, cred_id="", username="", password="", listener="DeathStar"
):
    output = await agent.execute(
        "powershell/management/spawnas",
        options={
            "Listener": listener,
            "CredID": str(cred_id),
            "UserName": username,
            "Password": password,
        },
    )

    results = output["results"]
    log.debug(results)
    return results
