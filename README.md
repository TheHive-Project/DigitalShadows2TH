# DigitalShadows2TH
Import DigitalShadows incident to TheHive

- `DigitalShadows/api.py` : main lib to get DigitalShadows incidents and intel-incidents
- `DigitalShadows/ds2markdown.py` : converting DigitalShadows incident in markdown (used in TheHive tasklog)
- `ds2th.py` : main program, get DigitalShadows incident or intel-incident and create a case in TheHive with a task containing all information.
- `config.py.template` : contains all the necessary information to connect to DigitalShadows API and TheHive API. All information is required.

## Prerequisite

Fill  `config.py` with all connection information to connect to DigitalShadows API and TheHive API.

## Usage

Identify an interesting incident on DigitalShadows website you want to import un TheHive. Note the incident number and run the following command on the system it sits :

```
$ ds2th.py -i <incidentNumber>
```
