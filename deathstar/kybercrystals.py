import os
import importlib
import logging
import pathlib
import pkg_resources

log = logging.getLogger("deathstar.kybercrystals")


class KyberCrystalException(Exception):
    pass


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
                        self.loaded.append(c)
                    except Exception as e:
                        log.error(f'Failed loading "{crystal_file}": {e}')

        log.debug(f"Loaded {len(self.loaded)} kyber crystal(s)")

    def __getattr__(self, name):
        for crystal in self.loaded:
            if name == pathlib.Path(crystal.__file__).stem:
                return crystal.crystallize
        raise KyberCrystalException(f"'{name}' crystal does not exist")
