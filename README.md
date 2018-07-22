![Supported Python versions](https://img.shields.io/badge/python-3-brightgreen.svg)

# DeathStar

DeathStar is a Python script that uses [Empire's](https://github.com/EmpireProject/Empire) RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techniques.

<p align="center">
  <img src="https://cloud.githubusercontent.com/assets/5151193/26531202/6229d238-43a1-11e7-87cf-3464f71eeb1e.gif" width="100%" alt="deathstar"/>
</p>

# Acknowledgments

Thanks [@DanHMcInerney](https://twitter.com/DanHMcInerney) for the insane amount of suffering you've went through to fix this

# How does it work?

See the accompanying blog post here:

https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html

# Installation

- First grab, install and run Empire:
```bash
git clone https://github.com/EmpireProject/Empire
cd Empire/setup && ./install.sh && cd ..
# Start the Empire console and RESTful API
python empire --rest --username empireadmin --password Password123
```

- Then grab, setup and run DeathStar:
```bash
git clone https://github.com/byt3bl33d3r/DeathStar
# Death Star is written in Python3
pip3 install -r requirements.txt
./DeathStar.py
```

# Usage

1. Run DeathStar
2. Get an Empire Agent on a box connected to a Domain
3. Go grab a coffee/tea/redbull, DeathStar will take care of everything else ;)

# How to fund my tea & sushi reserve

BTC: `1ER8rRE6NTZ7RHN88zc6JY87LvtyuRUJGU`

ETH: `0x91d9aDCf8B91f55BCBF0841616A01BeE551E90ee`

LTC: `LLMa2bsvXbgBGnnBwiXYazsj7Uz6zRe4fr`
