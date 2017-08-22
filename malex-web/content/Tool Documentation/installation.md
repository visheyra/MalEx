---
title: "Installation"
date: 2017-08-22T18:03:41+02:00
draft: true
---

# Install

MalEx is a python project which uses python2. In order to run properly malex need to be run in a virtualenv. You can find below all the instruction to install MalEx in a virtualenv

## Requirements

The following programs needs to be installed in order to install and run MalEx

* Python 2.7
* Virtualenv

## Step by step

1. Go to the root of the directory
2. execute command `virtualenv -p /path/to/python2 $some_name`
3. enter the virtualenv with `source $some_name/bin/activate`
4. execute command `pip2 install -r requirements.txt`
5. everything will work fine by now

## Dependancies

| package | usage | link |
| :---: | :---: | :---: |
| angr | reverse engineering framework | [angr](http://angr.io/)|
| angrutils | export visual representation of resources extracted by angr | [angrutils](https://github.com/axt/angr-utils)
| networkx | manipulation, study of structures and dynamics of complex networks also used by angr| [networkx](https://networkx.github.io/) |
| coloredlogs | fancy logger | [coloredlogs](https://coloredlogs.readthedocs.io/en/latest/)
