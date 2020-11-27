#!/bin/bash

FIREWALLCTL_PATH=$PWD/firewall/firewallctl.c
FIREWALL_PATH=$PWD/firewall.c

echo "Start installation for Basic-Firewall Kernel Module, Installing make and gcc..."
#apt-get update && apt-get install make gcc

echo "Looking for files..."
if [ ! -e $FIREWALL_PATH ]; then
  echo "Sorry we canno't find the firewall.c file, looked at $FIREWALL_PATH"
  echo "Cannot continue with the installing."
  exit -1
fi

if [ ! -e $FIREWALLCTL_PATH ]; then
  echo "Sorry we canno't find the firewall.c file, looked at $FIREWALL_PATH"
  echo "Cannot continue with the installation."
fi

echo "Installing firewall controller, compailing firewallctl.c ...."
gcc $FIREWALLCTL_PATH -o firewallctl.o
if [ ! -e $PWD/firewallctl.o ]; then
  echo "Compilation failed !"
  echo "Cannot continue with the installation."
  exit -1
fi

echo "Copy the firewallctl to /usr/bin\n"
mv $PWD/firewallctl.o /usr/bin/firewallctl
echo "Installing the firewall..."
make
if [ ! $? -eq 0 ]; then # Testing if make successed..
  echo "Compilation failed !"
  echo "Cannot continue with the installation."
  exit -1
fi

insmod firewall.ko

if [ $? -eq 0 ]; then # Testing if make successed..
  echo "Done."
  exit 0
fi


echo "Installation failed !"
echo "Cannot continue with the installing.\n"
exit -1




