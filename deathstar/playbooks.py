import logging
import yaml
import pathlib

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

log = logging.getLogger("deathstar.playbooks")


class PlaybookLoader:
    def __init__(self, play):
        self.play = play

    @classmethod
    async def from_yaml_file(self, path_to_playbook):
        play = yaml.load(path_to_playbook, Loader=Loader)
        return PlaybookLoader(play)

    @property
    async def postex(self):
        return self.play["postex"]

    @property
    async def domain_privesc(self):
        return self.play["domain_privesc"]
