import logging
import json
from rich import print
from argparse import RawTextHelpFormatter, RawDescriptionHelpFormatter

log = logging.getLogger("deathstar.utils")


class CustomArgFormatter(RawTextHelpFormatter, RawDescriptionHelpFormatter):
    pass


def beautify_json(obj) -> str:
    return "\n" + json.dumps(obj, sort_keys=True, indent=4, separators=(",", ": "))


def posh_object_parser(output):
    parsed_output = []

    blocks = list(filter(len, output.split("\r\n\r\n")))
    if blocks[-1].lower().find("completed") > 0:
        blocks.pop()

    for block in blocks:
        parsed_block = {}
        for entry in block.split("\r\n"):
            try:
                key, value = entry.split(":", 1)
            except ValueError:
                previous_key = list(parsed_block.keys())[-1]
                previous_value = parsed_block[previous_key]
                parsed_block[previous_key] = previous_value + entry.strip()
            else:
                parsed_block[key.strip().lower()] = value.strip()

        parsed_output.append(parsed_block)

    return parsed_output


def posh_table_parser(output):
    parsed_output = []

    blocks = list(filter(len, output.splitlines()))
    if blocks[-1].lower().find("completed") > 0:
        blocks.pop()

    title = blocks[0]
    word_start_positions = []
    for index, char in enumerate(title):
        if index == 0 and char != " ":
            word_start_positions.append(index)
        elif char != " " and title[index - 1] == " ":
            word_start_positions.append(index)

    keys = title.split()
    word_pos_to_key = {k: v.lower() for k, v in zip(word_start_positions, keys)}
    blocks = blocks[2:]

    for row in blocks:
        parsed_row_values = {}
        for start_pos in word_start_positions:
            for index, char in enumerate(row):
                if index == start_pos:
                    if char == " ":
                        parsed_row_values[word_pos_to_key[start_pos]] = ""
                        break

                if index > start_pos:
                    if index == (len(row) - 1) and char != " ":
                        parsed_row_values[word_pos_to_key[start_pos]] = row[
                            start_pos : index + 1
                        ]
                        break

                    if char == " " and row[index - 1] != " ":
                        parsed_row_values[word_pos_to_key[start_pos]] = row[
                            start_pos:index
                        ]
                        break

        parsed_output.append(parsed_row_values)

    return parsed_output


def print_win_banner():
    print("\n")
    print("[yellow]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[/yellow]")
    print("[yellow]=-=-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[/yellow]")
    print("[yellow]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[/yellow]")
    print("\n")
