#!/bin/bash


DS2TH_HOMEDIR=/opt/TheHive_feeders/Digitalshadows
ACCOUNT=thehive

RED=`tput setaf 1`
GREEN=`tput setaf 2`
NC=`tput sgr0`

ok() {
  echo " ${GREEN}[+] $*${NC}" >&2
}

ko() {
    echo "  ${RED}[-] $*${NC}" >&2
}

DEBUG=false


PROGRAM=$(cat << EOF

\n
DIGITALSHADOWS2TH INSTALLATION PROGRAM\n
\n
Settings:\n
\t- Installation path: $DS2TH_HOMEDIR\n
\t- System account: $ACCOUNT\n
\t- DEBUG: $DEBUG\n
EOF
)




if $DEBUG; 
then 
  DEBUG="" 
  WGET_OUTPUT="-v"
else 
  DEBUG="2>&1>/dev/null"
  WGET_OUTPUT="-q"
fi 


echo $PROGRAM 

## CREATE HOMEDIR
for path in config log ; 
do ( mkdir -p $DS2TH_HOMEDIR/$path $DEBUG && ok "$DS2TH_HOMEDIR/$path folders created" || ( ko "Failed to created $DS2TH_HOMEDIR/$path" && exit 1 ) );
done

## Download config files
wget -O $DS2TH_HOMEDIR/config/__init__.py https://raw.githubusercontent.com/TheHive-Project/DigitalShadows2TH/master/config/__init__.py $WGET_OUTPUT

if [ $? -eq 0 ]
then
	ok "__init__.py installed "
else
	ko "Failed to download and install __init__.py" 
	exit 1 
fi

wget -O $DS2TH_HOMEDIR/config/config.py https://raw.githubusercontent.com/TheHive-Project/DigitalShadows2TH/master/config/config.py.template $WGET_OUTPUT 

if [ $? -eq 0 ] 
then 
	ok "config.py installed "
else
       	ko "Failed to download and install config.py" 
	exit 1 
fi


## Check docker is installed 
if [ -f  $(which docker) ] 
then 
	ok "docker is installed"
else 
	ko "docker is not installed on your system or is not reachable"
	exit 1
fi


## Ensure docker can be use
if [ $($( grep docker /etc/group  | grep $USER)) ]
then 
	ok "user ${ACCOUNT} is allowed to use docker"
else 
	ko "user ${ACCOUNT} is not allowed to use docker. Add it to docker group ( usermod -G docker ${ACCOUNT} )"
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
\t- and run the feeder using the following command line:\n
\t docker run --rm --net=host --mount type=bind,source=$DS2TH_HOMEDIR/config,target=/app/config --mount type=bind,source=$DS2TH_HOMEDIR/log,target=/app/log thehiveproject/ds2th <OPTIONS>

EOF
)

echo $FINISH
