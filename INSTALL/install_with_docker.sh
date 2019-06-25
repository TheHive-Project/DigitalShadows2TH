#!/bin/bash

RED=`tput setaf 1`
GREEN=`tput setaf 2`
NC=`tput sgr0`


ok() {
    echo -e " ${GREEN}[+] $*${NC}" >&2
}

ko() {
    echo -e "  ${RED}[-] $*${NC}" >&2
}



## Check env vars
if [ ! ${FEEDERS_HOMEDIR} ] 
then
	FEEDERS_HOMEDIR=/opt/theHive_feeders
fi

if [ ! ${FEEDERS_SYSACCOUNT} ] 
then
	FEEDERS_SYSACCOUNT=thehive
fi

DS2TH_HOMEDIR=$FEEDERS_HOMEDIR/DigitalShadows2TH

PROGRAM=$(cat << EOF
\n
DIGITALSHADOWS2TH INSTALLATION PROGRAM\n
\n
Settings:\n
\t- Feeders root directory: $FEEDERS_HOMEDIR\n
\t- Installation path: $DS2TH_HOMEDIR\n
\t- Feeder system account: $FEEDERS_SYSACCOUNT\n
EOF
)


WGET_OUTPUT="-q"


echo -e $PROGRAM 

## CREATE HOMEDIR
folders='config log'

for path in $folders
do mkdir -p $DS2TH_HOMEDIR/$path
	if [ $? -eq 0 ]
	then 
		ok "$DS2TH_HOMEDIR/$path folders created" 
	else	
		echo $path
		ko "Failed to created $DS2TH_HOMEDIR/$path" 
		exit 1
	fi
done

## Download config files
wget $WGET_OUTPUT -O $DS2TH_HOMEDIR/config/__init__.py https://raw.githubusercontent.com/TheHive-Project/DigitalShadows2TH/master/config/__init__.py 

if [ $? -eq 0 ]
then
	ok "__init__.py installed "
else
	ko "Failed to download and install __init__.py" 
	exit 1 
fi

wget $WGET_OUTPUT -O $DS2TH_HOMEDIR/config/config.py https://raw.githubusercontent.com/TheHive-Project/DigitalShadows2TH/master/config/config.py.template

if [ $? -eq 0 ] 
then 
	ok "config.py installed "
else
       	ko "Failed to download and install config.py" 
	exit 1 
fi


## Check docker is installed 
if [ -x  "$(command -v docker)" ] 
then 
	ok "docker is installed"
else 
	ko "docker is not installed on your system or is not reachable"
	exit 1
fi


## Ensure docker can be use
 /bin/grep docker /etc/group | grep $FEEDERS_SYSACCOUNT > /dev/null
if [ $? -eq 0 ]
then 
	ok "user ${FEEDERS_SYSACCOUNT} is allowed to use docker"
else 
	ko "user ${FEEDERS_SYSACCOUNT} is not allowed to use docker. Add it to docker group ( usermod -G docker ${FEEDERS_SYSACCOUNT} )"
	exit 1
fi 

## Installing container
ok "Installing container: running docker pull thehiveproject/ds2th"
(docker pull thehiveproject/ds2th) \
&& ok "Container is installed" \
|| ( ko "Failed to install container" && exit 1 )

FINISH=$(cat << EOF
\n
DIGITALSHADOWS2TH INSTALLATION IS DONE!\n
\n
\t- edit $DS2TH_HOMEDIR/config/config.py\n
\t- and run the feeder using the following command line:\n\n
\t docker run --rm --net=host --mount type=bind,source=$DS2TH_HOMEDIR/config,target=/app/config --mount type=bind,source=$DS2TH_HOMEDIR/log,target=/app/log thehiveproject/ds2th <OPTIONS>
\n
EOF
)

echo -e $FINISH
