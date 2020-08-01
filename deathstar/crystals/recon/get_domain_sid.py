async def crystallize(agent):
    output = await deathstar.empire.modules.execute(
        "powershell/management/get_domain_sid", agent
    )

    return output["results"].splitlines()
