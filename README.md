# Basic-FireWall ![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/eliranmaman/Basic-Firewall) ![C/C++ CI](https://github.com/eliranmaman/Basic-FireWall/workflows/C/C++%20CI/badge.svg?branch=master) ![GitHub top language](https://img.shields.io/github/languages/top/eliranmaman/Basic-FireWall) ![GitHub](https://img.shields.io/github/license/eliranmaman/Basic-Firewall)
Basic-Firewall is an educational project, using to help me better understand how to write Kernel Modules. This project using netfilters
hook for manipulate the network packets. Basic-Firewall supporting only IPV-4.

The Basic-Firewall has its own controller (firewallctl), transferring the user request from the user space to the kernel space through a character device.

### My tool coverage 
* Blocking incoming network by PORT or IP filters, The hook for the incoming filters is at the Pre-Routing and testing where the packet arrived from.
* Blocking outgoing network by PORT or IP filters, The hook for the outgoing filters is at the Post-Routing and testing the packet destination.

### Requirements
* Debian based Linux distribution (Ubuntu xenial will be perfect)
* Kernel 4.4 (Tested on 4.4)

### Installation guide
Run the install.sh script from a terminal with sudo permissions.

##### Possible commands - 
* -h: Help & more information
* -n: The type of the network filter you would like to add / remove (IN or OUT)
* -t: The type of the filter you would like to add / remove (IP or PORT)
* -a: The type of the action you would like to perform (ADD or REMOVE)
* -i: Get all the system filters.
### Basic Usage
Please note, using the firewallctl required sudo premissions.
```bash
firewallctl -t [IN/OUT] -a [ADD/REMOVE] -t [IP/PORT] [IP/PORT]
```

* Add new filter for incoming network filtering by IP (127.0.0.1):
    ```bash
    firewallctl -n IN -t IP -a ADD 127.0.0.1
    ```
* Add new filter for incoming network filtering by PORT (1010):
    ```bash
    firewallctl -n IN -t PORT -a ADD 1010
    ```
* Add new filter for outgoing network filtering by IP (127.0.0.1):
  ```bash
  firewallctl -n OUT -t IP -a ADD 127.0.0.1
  ```
* Add new filter for outgoing network filtering by PORT (1010):
    ```bash
    firewallctl -n OUT -t PORT -a ADD 1010
    ```
* Remove existing filter for incoming network filtering by IP (127.0.0.1):
  ```bash
  firewallctl -n IN -t IP -a REMOVE 127.0.0.1
  ```
* Remove existing filter for incoming network filtering by PORT (1010):
    ```bash
    firewallctl -n IN -t PORT -a REMOVE 1010
    ```
* Remove existing filter for outgoing network filtering by IP (127.0.0.1):
  ```bash
  firewallctl -n OUT -t IP -a REMOVE 127.0.0.1
  ```
* Remove existing filter for outgoing network filtering by PORT (1010):
    ```bash
    firewallctl -n OUT -t PORT -a REMOVE 1010
    ```
* Getting all the system filters
    ```bash
    firewallctl -i
    ```
* Help
    ```bash
    firewallctl --help
    ```
### Further Filtering
Of course, you can clone & implement other filters.
