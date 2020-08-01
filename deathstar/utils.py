import logging
import json
from argparse import RawTextHelpFormatter, RawDescriptionHelpFormatter

log = logging.getLogger("deathstar.utils")


class CustomArgFormatter(RawTextHelpFormatter, RawDescriptionHelpFormatter):
    pass


def beautify_json(obj) -> str:
    return "\n" + json.dumps(obj, sort_keys=True, indent=4, separators=(",", ": "))
