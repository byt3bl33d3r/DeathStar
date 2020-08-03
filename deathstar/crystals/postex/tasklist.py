import re
from deathstar.utils import beautify_json

async def crystallize(agent):
    """
    I really wish there was another module we can use for this instead of just parsing tasklist output
    However, I also wish that cars could fly so maybe my expectations should be lower.

    Manaccia a San Cristoforo de Paola.
    """

    output = await agent.shell("tasklist")

    results = output['results']
    rows = results.split('\r\n')
    keys = rows[0].split()

    processes = []
    for entry in rows[2:]:
        # takes into account process names with multiple spaces
        values = re.sub(' +', ' ', entry.strip()).split()
        if len(values) == 6:
            processes.append(
                {k:v for k,v in zip(keys, values)}
            )

        elif len(values) <= 2:
            previous_process = processes[-1]
            for index,char in enumerate(entry):
                if char != " " and entry[index-1] == " ":
                    # It's a long ass username that got put on multiple lines
                    if index == 48:
                        previous_process["UserName"] = previous_process["UserName"] + values[-1].strip()
                        break

                    # It's a long ass process name that got put on multiple lines
                    if index == 1:
                        previous_process["ProcessName"] = previous_process["ProcessName"] + values[0].strip()
                        break

    for proc in processes:
        if proc['UserName'] == "N/A":
            proc["UserName"] = ""

    log.debug(beautify_json(processes))
    return processes
