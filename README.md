# DeathStar

<p align="center">
  <img src="https://user-images.githubusercontent.com/5151193/88892241-ddc6d700-d21a-11ea-9c37-3cffed86e2f8.png" alt="DeathStar" height="300"/>
</p>

DeathStar is a Python script that uses [Empire's](https://github.com/BC-SECURITY/Empire) RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs.

# Sponsors
[<img src="https://www.blackhillsinfosec.com/wp-content/uploads/2016/03/BHIS-logo-L-300x300.png" width="130" height="130"/>](https://www.blackhillsinfosec.com/)
[<img src="https://handbook.volkis.com.au/assets/img/Volkis_Logo_Brandpack.svg" width="130" hspace="10"/>](https://volkis.com.au)
[<img src="https://user-images.githubusercontent.com/5151193/85817125-875e0880-b743-11ea-83e9-764cd55a29c5.png" width="200" vspace="21"/>](https://qomplx.com/blog/cyber/)
[<img src="https://user-images.githubusercontent.com/5151193/86521020-9f0f4e00-be21-11ea-9256-836bc28e9d14.png" width="250" hspace="20"/>](https://ledgerops.com)
[<img src="https://user-images.githubusercontent.com/5151193/102297674-e6d7ec80-3f0c-11eb-982f-cc5d13b0e9ce.jpg" width="250" hspace="20"/>](https://www.guidepointsecurity.com/)
[<img src="https://user-images.githubusercontent.com/5151193/95542303-a27f1c00-09b2-11eb-8682-e10b3e0f0710.jpg" width="200" hspace="20"/>](https://lostrabbitlabs.com/)

# Table of Contents
- [DeathStar](#deathstar)
  * [Motivation](#motivation)
  * [New Features](#new-features)
  * [Official Discord Channel](#official-discord-channel)
  * [Installation](#installation)
    + [Docker](#docker)
    + [Python Package](#python-package)
    + [Development Install](#development-install)
  * [Usage](#usage)
  * [Extending Functionality](#extending-functionality)
    + [Kyber Crystals](#kyber-crystal-plugin-system)
    + [Creating Kyber Crystals](#creating-kyber-crystals)
    + [Crystal Injection](#crystal-injection)
  * [Defense & Detection](#defense--detection)
  * [Feature Roadmap & Interest Check](#feature-roadmap--interest-check)

## Motivation

The primary motivation behind the creation of this was to demonstrate how a lot of the commonly exploited Active Directory misconfiguration can be chained together to gain Administrator level privileges in an automated fashion (akin to a worm).

While there are definitely a lot more things that could be taken advantage of (including server side vulnerabilities such as MS17-010), DeathStar mainly focuses on exploiting misconfigurations/vulnerabilities which have a very low probability of causing any sort of system/network stability issues.

Version 0.2.0 is a complete re-write of the original, implements a [plugin system](#kyber-crystals) (among lots of [other things](#new-features)) which allows anyone to extend it's functionality if so desired. 

Additionally, it now supports Active Directory environments with multiple Forests/Domains and has an "Active Monitoring" feature which allows it to adapt it's attack path based on real-time changes in the network.

## New Features

Version 0.2.0 is a complete re-write of the original DeathStar script which I released in 2017.

Here's a complete list of the new and shiny things:

- Completely Asynchronous (uses AsyncIO)
- Has the ability to get Domain Admin & Enterprise Admin rights (as supposed to just Domain Admin rights)
- Supports environments with Multiple Active Directory Domains & Forests
- Implements the Kyber Crystal Plugin system that allows anybody to extend it's functionality.
- Active Monitoring: this allows DeathStar to poll all compromised machines for new logins and adapt attack paths accordingly.
- Uses the [BC-Security Empire Fork](https://github.com/BC-SECURITY/Empire)

## Official Discord Channel

Come hang out on the Porchetta Industries Discord server!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)

## Installation

The author recommends using Docker or PipX.

### Docker

```
docker run --rm -it byt3bl33d3r/deathstar -u <empire_username> -p <empire_password> --api-host <empire_ip>
```

Since Empire has a Docker image, you could totally write Docker Compose file to get both up and running instantly :)

### Python Package

**This project is available on Pypi under the name `deathstar-empire` because someone else aleady has a project called deathstar**

```
python3 -m pip install --user pipx
pipx install deathstar-empire
```

### Development Install

You should only be installing DeathStar this way if you intend to hack on the source code. You're going to Python 3.8+ and [Poetry](https://python-poetry.org/). Please refer to the Poetry installation documentation in order to install it.

```console
git clone https://github.com/byt3bl33d3r/DeathStar && cd WitnessMe
poetry install
```

## Usage

First, you're going to need to install [BC-Security's Empire fork](ttps://github.com/BC-SECURITY/Empire), please refer to it's documentation on how to get it installed.

You then need to start Empire with it's RESTful API enabled, you should also specify a username and password as this is needed for DeathStar to interact with it.

```
python empire --rest --username <empire_username> --password <empire_password>
```

Point DeathStar to Empire and give it the same credentials you specified before. By default, it'll attempt to find Empire's RESTful API on the loopback interface, you can override this using the ```--api-host``` flag.

```
deathstar -u <empire_username> -p <empire_password> --api-host <empire_ip>
```

DeathStar will login to Empire's API and automatically start a listener for you. Now all you have to do is get an Empire agent on a box! DeathStar will immediately take over and do it's thang.

## Extending Functionality

The DeathStar is powered by Kyber Crystals! The Kyber Crystal Plugin System allows anyone to extend DeathStar's functionality and enable it to use any of Empire's available modules.

After creating a Kyber crystal, you have to inject the crystal into Deathstar's reactor using a process called Crystal Injection (this is currently a manual process, see the [appropriate section](#crystal-injection)).

## Kyber Crystal Plugin System

Kyber Crystals serve as an abstraction layer between Empire's module output and DeathStar's internal logic. In practical terms, they're responsible for initiating the HTTP API calls to run an Empire module, parse their output and return structured data (JSON) that DeathStar's internal logic can use.

## Creating Kyber Crystals

A Kyber Crystal is made up of a single Python file which defines an entry coroutine (asynchronous function) named `crystallize`.

This function **must** be coroutine and have the ```async``` keyword. Additionally, it's first argument must always be the Empire Agent Object to run the module on.

Kyber Crystals are automatically loaded on runtime from the `crystals` folder and are organized by the task performed and the empire module they run & parse.

Since an example is worth a thousand words, below is the Kyber Crystal code responsible for running the `get_domain_controller` Empire module and can be found in the `deathstar/crystals/recon/get_domain_controller.py` file:

```python
from deathstar.utils import posh_object_parser, beautify_json


async def crystallize(agent):
    output = await agent.execute(
        "powershell/situational_awareness/network/powerview/get_domain_controller"
    )

    results = output["results"]
    parsed_obj = posh_object_parser(results)
    log.debug(beautify_json(parsed_obj))
    return parsed_obj
```

As of writing, Empire modules output non-structured data in the form of "stringified" PowerShell Objects or Tables. This is where the `posh_object_parser` and `post_table_parser` functions come in and take care of turning those PoSH objects/tables into JSON (the code for these functions is awful, don't look at it). 

These functions don't account for every edge case, so if you see some values missing in the returned JSON you're probably going to have to parse the module output manually.

The end result is the coroutine returning the JSON output to be parsed by DeathStar's internal logic.

The `log` variable is injected at runtime into each plugin for debugging purposes. You can enable debug output by passing the ```--debug``` flag to DeathStar.

## Crystal Injection

Once you created your Kyber Crystal you need to inject it into the reactor so it can be part of the "pwning process". As of writing this has to be done a manually and involves modifying the code in the main `deathstar.py` file.

In the `deathstar.py` file there's a `DeathStar` class which has 4 async methods (coroutines), which are responsible for most of the internal logic. Depending on what your Kyber Crystal does, you're probably going to want to run it within one of these 4 coroutines:

- `planetary_recon`: Recon coroutine responsible for performing the initial domain information gathering
- `launch_hunter_killers`: Domain Privesc coroutine, executes the domain privesc stuff
- `galaxy_conquest`: Lateral movement coroutine
- `fire_mission`: Active Monitoring coroutine, this polls each agent for new logins, performs process injection and prioritizes high-value targets (e.g. machines with admins logged in)

Could have I made this easier? Yes, but it would have required a ton more work and honestly I don't have any clue if people are even interested in this. See the [Feature Roadmap & Interest Check]() section.

## Defense & Detection

DeathStar merely automates Empire, so to detect DeathStar you need to detect Empire. Consequentially your standard "Offensive PowerShell Tradecraft" defenses and detections apply.

Generally speaking, this involves making sure you have an EDR solution with AMSI integration, have PowerShell Logging enabled (ScriptBlock, Module and Transcription level logging) and if possible enable PowerShell Constrained Language Mode. While none of these defenses are "bullet-proof" they significantly raise the bar and make life harder for attackers. Defense in depth is the key here.

**DeathStar, by default, does not enable any of the AMSI/Logging bypasses that Empire has and doesn't enable any setting(s) that could aid in evading any of the modern PowerShell defenses.**

If someone using DeathStar doesn't know what they're doing, they'll get caught the second they launch the initial Empire Agent on any modern Windows 10 system. 

## Feature Roadmap & Interest Check

There's a lot that could be done with DeathStar, the dream would be to have a tool which can aid in Threat Hunting. It can definitely still be used for Offensive purposes during pentests but I'm seeing the future of this being a "Purple Team" tool.

Some of the main features I'd love would be:

- Configuration file to allow tweaking some of Empire's settings regarding evasion.
- Have YAML "Playbooks" which would allow users to select which TTPs/Empire Modules to use during the "pwning" process.
- Make an easier way to add Kyber Crystals to the main logic (without requiring code modifications)
 
 These would all require a ton more work, and I'm not even sure if people find this useful as it is. If you like the idea and think it could be useful, feel free to ping me on [Twitter](https://twitter.com/home), [sponsor me on Github](https://github.com/sponsors/byt3bl33d3r/) or send a PR.
