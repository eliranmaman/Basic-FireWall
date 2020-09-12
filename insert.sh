#!/bin/bash

sudo cp firewall/firewall.c firewall.c
sudo rmmod firewall
make
sudo insmod firewall.ko
sudo chmod 666 /dev/network_firewall_device

