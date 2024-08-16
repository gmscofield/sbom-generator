# Getting Started

## Create a virtual environment and install necessary libraries

Check your python version and pip version.

```shell
python3 -m pip --version
```

Then create a virtual environment.

```shell
sudo apt install python3-venv && \  
python3 -m pip install --user virtualenv && \  
python3 -m venv env && \
source ./env/bin/activate
```

Finally install all the needed libraries with requirements.txt.

```shell
python3 -m pip install -r requirements.txt
```

## Usage

The input of the tool is filesystem(local file directory), and the output is a SBOM document.

Options:

    -v, --version       Version of the tool
    -i, --input         Input path of software package, default is current path
    -o, --outfile       Output file path of SBOM, default is stdout
    -f, --format        Output format of SBOM, choose from txt or json, default is txt
    -l, --level         SBOM level, choose from 1, 2 or 3, default is basic level of SBOM (Level 1)
    --model             SBOM Model, choose from SPDX, CycloneDX or OSSBOM, default is OSSBOM
    --tree              Present the whole Dependency Tree in the SBOM document

Example:

```shell
cd ..
python -m SbomGT -i /package -o /root/test/ -f json -l 1 --model ossbom
```