# DeathStar

DeathStar is a Python script that uses [Empire's](https://github.com/EmpireProject/Empire) RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techinques.

<p align="center">
  <img src="https://cloud.githubusercontent.com/assets/5151193/26531202/6229d238-43a1-11e7-87cf-3464f71eeb1e.gif" width="100%" alt="deathstar"/>
</p>

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
