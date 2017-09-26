# DigitalShadows2TH
Import DigitalShadows incidents and intel-incidents into TheHive alerts.

- `DigitalShadows/api.py` : main lib to get DigitalShadows incidents and intel-incidents
- `ds2markdown.py` : converting DigitalShadows incidents data in markdown (used in TheHive alerts)
- `ds2th.py` : main program, gets DigitalShadows incidents or intel-incidents and creates alerts in TheHive with a description containing all information, and observables if any.
- `config.py.template` : contains all the necessary information to connect to DigitalShadows API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill the blanks, proxies and information (api key, url, accounts) regarding DigitalShadows API and TheHive API.

## Usage

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

- The program comes with 2 commands : `inc` to fetch incidents or intel-incidents by IDs, and `find` to fetch published incidents and/or intel-incidents during last M minutes. 
- `-d` : add this switch to get `debug` information in `ds2th.log` file

### Retreive incidents or intel-incidents spedified by ID - use the `inc` command

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

- `./ds2th.py inc -i 1234567 2345678` : fetch incidents with IDs 1234567 and 2345678
- `./ds2th.py inc -I 1234567 2345678` : fetch intel-incidents with IDs 1234567 and 2345678

### Retreive incidents and intel-incidents published during last `M` minutes - use the `find` command

```
$ ./ds2th.py find -h
usage: ds2th.py find [-h] -s M [-m] [-i] [-I]

optional arguments:
  -h, --help       show this help message and exit
  -s M, --since M  Get all incident since last [M] minutes
  -m, --monitor    active monitoring
  -i               Get Digital Shadows incidents only
  -I               Get Digital Shadows intel-incidents only
```

- `./ds2th.py find -s 20` retrieves incidents and intel-incidents published during last 20 minutes
- `-i` and `-I` are switches you can specified if you want to fetch only incidents or intel-incidents. If none, both are retrieved.
- `m` is a switch that creates a `ds2th.status`. Useful is you want to add the program as a cron job and monitor it. 

### Use cases

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

- Add a cron job and check for new published incidents every 10 min

```
*/10    *   *   *   * /path/to/ds2th.py find -s 15
```

- Enable logging

```
*/10    *   *   *   * /path/to/ds2th.py -d find -s 15
```

This will create a `ds2th.log` in the folder of the main program.

### Monitoring 

- Monitor the feeder

```
*/10    *   *   *   * /path/to/ds2th.py find -s 15 -m
```

The first time, it will create an empty `ds2th.status` in the folder of the main program. The Program adds `SUCCESS` when it terminates successfully. The birth date of this file is renewed at the start of the next execution, and emptied.
