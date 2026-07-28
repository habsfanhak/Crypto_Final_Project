## Cryptography Final Project

This project implements a simple session between Alice and Bob, and tests the implementation with the project notebook serving as the space where an attacker may hypothetically intercepts and carry out a variety of attacks.


### Project Structure
- `project.ipynb`, Demonstration notebook, inherits the user class, directs all operations and demonstrates attacker behaviour
- `source/user.py`, User class implementation, does all under the hood work for protocols
- `setup/`, Environments and dependencies

### Requirements

- Python 3.12
- `cryptography` 49.0.0

Run the following commands from the project root.

#### Option 1 (python)

If Python 3.12 is already installed and an isolated environment is not required:

```
python -m pip install cryptography==49.0.0
```

#### Option 2: Conda

```
conda env create -f setup/environment.yml
conda activate crypto-final
```

#### Option 3 (venv)
```
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r setup/requirements.txt
```

### Running the project

Open the demonstration notebook:

`jupyter notebook project.ipynb`

