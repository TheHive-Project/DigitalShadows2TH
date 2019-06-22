# DigitalShadows2TH: Digital Shadows Alert Feeder for TheHive 

[Digital Shadows](https://www.digitalshadows.com/) is a commercial Threat Intelligence provider which, according to their website:

> monitors, manages and remediates digital risk across the widest range of data sources within the open, deep, and dark web to protect an organization’s business, brand, and reputation using several criteria, data analytics and human actions, their SearchLight service can notify customers about *incidents* and *intel-incidents*. 

The service offers an API which can be leveraged to consume these two types of information and programmatically send them as alerts to [TheHive](https://github.com/CERT-BDF/TheHive), a popular free and open source Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.

DigitalShadows2TH is a free, open source Digital Shadows alert feeder for TheHive. You can use it to import Digital Shadows *incidents* and *intel-incidents* as alerts in TheHive, where they can be previewed and transformed into new cases using pre-defined incident response templates or added into existing ones.

DigitalShadows2TH is written in Python 3 by TheHive Project.

## Overview

DigitalShadows2TH is made of several parts:

- `DigitalShadows/api.py` : the main library to interact with the Digital Shadows Searchlight API and fetch *incidents* and *intel-incidents*.
- `ds2markdown.py` : a program which converts Digital Shadows data into Markdown as used by alerts in TheHive.
- `config/config.py.template` : a configuration template which contains all the necessary information to connect to the APIs of Digital Shadows and TheHive. All information is required.
- `ds2th.py` : the main program. It gets Digital Shadows *incidents* or *intel-incidents* and creates alerts in TheHive with a description containing all relevant information, and observables if any.

## Prerequisites

You'll need Python 3.5s+, `python-magic` and  `requests` libraries and [TheHive4py](https://github.com/CERT-BDF/TheHive4py),  a Python client for TheHive.

Clone the repository then copy the `config/config.py.template` file as `config/config.py` and fill in the blanks: proxies if applicable, API keys, URLs, accounts pertaining to your Digital Shadows subscription and your instance of TheHive.

**Note**: you need TheHive 2.13 or later and an account with the ability to create alerts.

Then install the Python requirements:

`$ pip3 install -r requirements.txt`

The feeder can also be run using docker. Please refer to this [section](#docker) for more details.

## Configure the feeder

inside the `config` folder, copy the `config.py.sample` to `config.py` and fill the blanks.

```python
DigitalShadows = {
    'proxies':{
        'http': '',
        'https': ''
    },
    'url':'',
    'ds_key':'',
    'ds_secret':'',
    'verify':True,
    'fulltext':'true'
    'log_file':'log/ds2th.log',
    'monitoring_file':'log/ds2th.status'
}

TheHive = {
  'proxies':{
      'http': '',
      'https': ''
  },
    'url':'',
    'key':'',
    'template': {
        'default':''
    }
}
```

Several TheHive case templates can be defined, depending on DigitalShadows incident type.
From the DigitalShadows [API documentation](https://portal-digitalshadows.com/learn/api/latest/incidents/get/incidents/%7Bid%7D), incidents can be any type of : 
```
DATA_LEAKAGE
CYBER_THREAT
PHYSICAL_SECURITY
SOCIAL_MEDIA_COMPLIANCE
BRAND_PROTECTION
INFRASTRUCTURE
```

To configure a custom case template for a type of incident, just update the configuration for TheHive like this :

```python
  'templates': {
        'default':'DefaultCaseTemplateForDigitalShadows',
        'DATA_LEAKAGE': 'TheHiveCaseTemplateForDataLeaks'
    }
```

## Usage

Once your configuration file `config.py` is ready and set up in the `config` folder, use the main program to fetch or find Digital Shadows (DS) *incidents* and *intel-incidents*:

```
./ds2th.py -h
usage: ds2th.py [-h] [-d] {inc,find} ...

Get DS alerts and create alerts in TheHive

positional arguments:
  {inc,find}   subcommand help
    inc        fetch incidents or intel-incidents by ID
    find       find incidents and intel-incidents in time

optional arguments:
  -h, --help   show this help message and exit
  -d, --debug  generate a log file and and active debug logging
```

The program comes with 2 commands:
- `inc` to fetch *incidents* or *intel-incidents* by their IDs
- `find` to fetch *incidents* and/or *intel-incidents* published during 
the last M minutes. 

If you need debbuging information, add the `d`switch and the program will 
create a file called `ds2th.log`. It will be created in the `log` folder by default. This can be set up in the `config/config.py` configuration file.

### Retrieve incidents or intel-incidents specified by their ID

```
./ds2th.py inc -h
usage: ds2th.py inc [-h] [-i ID [ID ...]] [-I ID [ID ...]]

optional arguments:
  -h, --help            show this help message and exit
  -i ID [ID ...], --incidents ID [ID ...]
                        Get DS incidents by ID
  -I ID [ID ...], --intel-incidents ID [ID ...]
                        Get DS intel-incidents by ID
```

- `./ds2th.py inc -i 1234567 2345678` : fetch incidents with IDs 1234567 and 2345678.
- `./ds2th.py inc -I 1234567 2345678` : fetch intel-incidents with IDs 1234567 and 2345678.

### Retrieve incidents and intel-incidents published during the last `M` minutes

```
./ds2th.py find -h
usage: ds2th.py find [-h] -l M [-m] [-i] [-I]

optional arguments:
  -h, --help      show this help message and exit
  -l M, --last M  Get all incidents published during the last [M] minutes
  -m, --monitor   active monitoring
  -i              Get Digital Shadows incidents only
  -I              Get Digital Shadows intel-incidents only

```

- `./ds2th.py find -l 20` retrieves incidents and intel-incidents published during the last 20 minutes.
- `-i` and `-I` are switches you can specified if you want to fetch only incidents or intel-incidents. If no switch is used, both are retrieved.
- `m` is a switch that creates a `ds2th.status` file. This is useful if you want to add the program as a cron job and monitor it. 

### Use Cases

- Fetch incident #123456

```
$ ./ds2th.py inc -i 123456
```

- Fetch intel-incident #123456

```
$ ./ds2th.py inc -I 123456
```

- Fetch intel-incident #123456 and incident #2345567

```
$ ./ds2th.py inc -I 123456 -i 234567
```

- Add a cron job and check for new published incidents every 10 mins:

```
*/10    *   *   *   * /path/to/ds2th.py find -l 15
```

- Enable logging:

```
*/10    *   *   *   * /path/to/ds2th.py -d find -l 15
```

This will create a `ds2th.log` file in the `log` folder of the main program.

### Monitoring 

- Monitor the feeder

```
*/10    *   *   *   * /path/to/ds2th.py find -l 15 -m
```

The monitoring switch makes the program "touch" a file named `ds2th.status` once it has successfully finished. This file is set by default in the `log`folder. To monitor it, just check the modification date of this file and compare it to the frequency used in your crontab entry.

## Docker

The program can be run using Docker. You can pull the docker or build your own.

 

### Pull the container

```bash
docker pull thehiveproject/ds2th:latest
```

### Or build the container

If you want to build you own docker, in the project folder run the following command:

```bash
docker build --no-cache  -t thehiveproject/ds2th .
```

### Prepare your environment and configure the feeder

Choose the folder where the configuration and logs will reside. (`/opt/TheHive_feeders/Digitalshadows/` in our documentation)

```bash
DS2TH_HOMEDIR = /opt/TheHive_feeders/Digitalshadows/
mkdir -p $DS2TH_HOMEDIR/{config,log}
wget -O $DS2TH_HOMEDIR/config/config.py https://raw.githubusercontent.com/TheHive-Project/DigitalShadows2TH/master/config.py.template
```

and edit `$DS2TH_HOMEDIR/config/config.py` following instructions in #configure-the-feeder. 

### Run with docker 

```bash
docker  run \
--rm\
--net=host \
--mount type=bind,source="$DS2TH_HOMEDIR"/config,target=/app/config \
--mount type=bind,source="$DS2TH_HOMEDIR"/log,target=/app/log \
thehiveproject/ds2th OPTIONS
```

### Run it with cron 

For example: 
```
*/10    *   *   *   * docker run --rm --net=host --mount type=bind,source="$DS2TH_HOMEDIR"/config,target=/app/config --mount type=bind,source="$DS2TH_HOMEDIR"/log,target=/app/log thehiveproject/ds2th -d find -l 15 -m
```

# License

DigitalShadows2TH is an open source and free software released under the [AGPL](LICENSE) (Affero General Public License). We, TheHive Project, are committed to ensure that DigitalShadows2TH will remain a free and open source project on the  long-run.

# Updates

Information, news and updates are regularly posted on [TheHive Project Twitter account](https://twitter.com/thehive_project) and on [the blog](https://blog.thehive-project.org/).

# Contributing

Please see our [Code of conduct](code_of_conduct.md). We welcome your contributions. Please feel free to fork the code, play with it, make some patches and send us pull requests via [issues](https://github.com/CERT-BDF/DigitalShadows2TH/issues).

# Support

Please [open an issue on GitHub](https://github.com/CERT-BDF/DigitalShadows2TH/issues) if you'd like to report a bug or request a feature. We are also available on [Gitter](https://gitter.im/TheHive-Project/TheHive) to help you out.

If you need to contact the project team, send an email to <support@thehive-project.org>.

**Important Note**:

- If you have problems with [TheHive](https://github.com/CERT-BDF/TheHive), please [open an issue on its dedicated repository](https://github.com/CERT-BDF/TheHive/issues/new).

# Community Discussions

We have set up a Google forum at <https://groups.google.com/a/thehive-project.org/d/forum/users>. To request access, you need a Google account. You may create one [using a Gmail address](https://accounts.google.com/SignUp?hl=en) or [without it](https://accounts.google.com/SignUpWithoutGmail?hl=en).

# Website

<https://thehive-project.org/>
