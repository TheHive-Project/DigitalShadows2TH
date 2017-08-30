# DigitalShadows2TH
Import DigitalShadows incident to TheHive

- `DigitalShadows/api.py` : main lib to get DigitalShadows incidents and intel-incidents
- `ds2markdown.py` : converting DigitalShadows incident in markdown (used in TheHive alerts)
- `ds2th.py` : main program, get DigitalShadows incident or intel-incident and create an alert in TheHive with a description containing all information, and observables if any.
- `config.py.template` : contains all the necessary information to connect to DigitalShadows API and TheHive API. All information is required.

## Prerequisite

Copy `config.py.template` into `config.py` and fill all connection information needed to connect to DigitalShadows API and TheHive API.

## Usage

- Retrieve incidents and intel-incidents from DigitalShadows every \<time\> minutes:

```
$ ds2th.py -t  <time>
```
- Check for new incidents every 10 minutes (`-t 15` is used to be sure to retrieve all alerts created in the last 10 minutes) :

```
*/10    *   *   *   * /path/to/ds2th.py -t 15
```

- Enable logging and add INFO logs :

```
*/10    *   *   *   * /path/to/ds2th.py -t 15 --log=INFO
```

- Enable logging and add DEBUG logs :

```
*/10    *   *   *   * /path/to/ds2th.py -t 15 --log=DEBUG
```

When enabled, logs are written in the program's folder, in file named `ds2th.log`.
