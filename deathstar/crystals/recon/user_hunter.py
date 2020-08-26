from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent, group):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/user_hunter",
        timeout=-1,
        options={"UserGroupIdentity": group},
    )

    results = output["results"]
    parsed = posh_object_parser(results)

    # We really only care about the SessionFromName and ComputerName fields...
    sessions = []

    sessions.extend(
        [session["computername"] for session in parsed if session["computername"]]
    )
    sessions.extend(
        [session["sessionfromname"] for session in parsed if session["sessionfromname"]]
    )

    log.debug(beautify_json(sessions))
    return sessions
