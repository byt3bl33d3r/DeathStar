import re
import traceback
from deathstar.kybercrystals import KyberCrystalException
from deathstar.utils import beautify_json


async def crystallize(agent):
    """
    I really wish there was another module we can use for this instead of just parsing tasklist output
    However, I also wish that I could ride a giraffe to work so maybe my expectations should be lower.
    """

    output = await agent.shell("ps")
    results = output["results"]
    processes = []

    try:
        if results.startswith("error running command"):
            raise KyberCrystalException(
                "Tasklist command decided not to work right now, please try again later..."
            )

        blocks = list(filter(len, results.splitlines()))

        for row in blocks[2:]:
            if len(row.split()) == 1:
                prev_value = processes[-1]["username"]
                processes[-1]["username"] = prev_value + row.split()[0]
                continue

            parts = list(filter(len, re.sub(r"\s{2,}", "__", row).split("__")))
            pid, arch = parts[1].split()
            pname = parts[0]
            if len(parts) == 4:
                username = parts[2]
                memusage = parts[3]
            elif len(parts) == 3:
                memusage = re.findall(r"\s(.*\d\sMB)", parts[2])[0]
                username = parts[2].split()[0]

            processes.append(
                {
                    "processname": pname,
                    "pid": pid,
                    "arch": arch,
                    "username": username,
                    "memusage": memusage,
                }
            )

    except Exception as e:
        log.error(f"Error parsing tasklist output: {e} output:\n {results}")
        log.error(traceback.format_exc())

    for proc in processes:
        if proc["username"] == "N/A":
            proc["username"] = ""

    log.debug(beautify_json(processes))
    return processes
