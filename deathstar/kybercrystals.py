import os
import importlib
import logging
import pathlib
import pkg_resources
from rich.logging import RichHandler
from contextvars import ContextVar

log = logging.getLogger("deathstar.kybercrystals")


class KyberCrystalException(Exception):
    pass


class KyberContextFilter(logging.Filter):
    AgentVar = ContextVar("agent")

    def filter(self, record):
        agent = KyberContextFilter.AgentVar.get()
        record.agent = agent.name
        record.agent_username = agent.username
        return True


def kyberlogger(func, name):
    async def wrapper(*args, **kwargs):
        agent = args[0] or kwargs.get("agent")
        log = logging.getLogger(f"deathstar.kybercrystals.{name}")
        log.filters[0].AgentVar.set(agent)
        log.debug(f"Running {name}")
        return await func(*args, **kwargs)

    return wrapper


class KyberCrystals:
    def __init__(self, deathstar):
        self.deathstar = deathstar
        self.crystal_location = pathlib.Path(
            pkg_resources.resource_filename(__name__, "crystals")
        )

        self.loaded = []
        self.get_crystals()

    def is_sane(self, module):
        if not hasattr(module, "crystallize"):
            raise KyberCrystalException(
                "Crystal does not contain a 'crystallize' coroutine"
            )

    def load(self, path):
        module_spec = importlib.util.spec_from_file_location("crystal", path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        self.is_sane(module)
        return module

    def get_crystals(self):
        log_filter = KyberContextFilter()
        handler = RichHandler()
        handler.setFormatter(
            logging.Formatter(
                "[{name}] Agent: {agent} User: {agent_username} => {message}",
                style="{"
            )
        )

        for root, _, files in os.walk(self.crystal_location):
            for crystal in files:
                crystal_file = self.crystal_location / root / crystal
                if (
                    crystal_file.suffix == ".py"
                    and not crystal_file.stem == "example"
                    and not crystal_file.stem.startswith("__")
                    and crystal_file.name != "__init__.py"
                ):
                    try:
                        c = self.load(crystal_file)
                        c.deathstar = self.deathstar
                        c.log = logging.getLogger(
                            f"deathstar.kybercrystals.{crystal_file.stem}"
                        )
                        c.log.propagate = False
                        c.log.addHandler(handler)
                        c.log.addFilter(log_filter)

                        self.loaded.append(c)
                    except Exception as e:
                        log.error(f'Failed loading "{crystal_file}": {e}')

        log.debug(f"Loaded {len(self.loaded)} kyber crystal(s)")

    def __getattr__(self, name):
        for crystal in self.loaded:
            if name == pathlib.Path(crystal.__file__).stem:
                return kyberlogger(crystal.crystallize, name)
        raise KyberCrystalException(f"'{name}' crystal does not exist")
