import pytest
import logging

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s - %(message)s"))

log = logging.getLogger("deathstar")
log.setLevel(logging.DEBUG)
log.addHandler(handler)

