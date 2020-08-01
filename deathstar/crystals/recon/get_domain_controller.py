async def crystallize(agent):
    output = await deathstar.empire.modules.execute(
        "powershell/situational_awareness/network/powerview/get_domain_controller",
        agent,
    )

    results = output["results"].splitlines()
