# DigitalShadows2TH
Import DigitalShadows incident to TheHive

- `DigitalShadows/api.py` : main lib to get DigitalShadows incidents and intel-incidents
- `ds2markdown.py` : converting DigitalShadows incident in markdown (used in TheHive tasklog)
- `ds2th.py` : main program, get DigitalShadows incident or intel-incident and create a case in TheHive with a task containing all information.
- `config.py.template` : contains all the necessary information to connect to DigitalShadows API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to DigitalShadows API and TheHive API.

## Usage


```
$ ds2th.py -t  <time> --log=<FACILITY>
```
