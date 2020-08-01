async def crystallize(agent, group_sid, recurse=True):
    output = await deathstar.empire.modules.execute(
        "powershell/situational_awareness/network/powerview/get_group_member",
        agent,
        options={
            "Identity": group_sid,
            "Recurse": str(
                recurse
            ).lower(),  # Empire doesn't do any type checking or type conversions...
        },
    )

    results = output["results"]
    return results
