# spystrap
A Steam client bootstrapper bootstrapper, poorly implemented in Python.

## why this exists
I have no idea.

## Current Status
- [x] Downloads client package information from the Valve CDN.
- [x] Extracts package files to a target directory.
- [ ] Fails to produce a launchable, working Steam client.


# install
Clone the repo
```bash
git clone https://github.com/m4dEngi/spystrap.git
cd spystrap
```

Create venv and install requirements
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

# usage
Run spystrap and point it to `install_path` where you want steam client files to be downloaded
```bash
python spystrap.py -i <install_path>
```
And if you're lucky enough, it will download and extract client into the specified folder...

... but no amount of luck will make it produce a working client install at the moment.


# acknowledgements
This project's implementation relies heavily on information gathered from the work of others:
- @johndrinkwater vzip file format https://gist.github.com/johndrinkwater/8944787
- @yaakov-h https://github.com/yaakov-h/vunzip
