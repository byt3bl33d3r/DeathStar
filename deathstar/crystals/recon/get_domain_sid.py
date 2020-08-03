async def crystallize(agent):
    output = await agent.execute("powershell/management/get_domain_sid")

    domain_sid = output["results"].splitlines()[0]
    log.debug(domain_sid)
    return domain_sid
