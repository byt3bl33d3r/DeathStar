# DeathStar

DeathStar is a Python script that uses [Empire's](https://github.com/EmpireProject/Empire) RESTful API to automate gaining Domain Admin rights in an Active Directory environments using a variety of techinques.

# Installation

Currently, for Death Star to work you're going to have to install my fork of Empire until this [pull request](https://github.com/EmpireProject/Empire/pull/531) gets merged and the changes get pushed to master. The fork contains some API and back-end database fixes for scripts that interact with the RESTful API.

- First grab, install and run Empire:
```bash
git clone https://github.com/byt3bl33d3r/Empire
cd Empire/setup && ./install.sh && cd ..
# Start the Empire console and RESTful API
python empire --rest --username empireadmin --password Password123
```

Then grab, setup and run DeathStar:
```bash
git clone https://github.com/byt3bl33d3r/DeathStar
# Death Star is written in Python3
pip3 install -r requirements.txt
./DeathStar.py
```
