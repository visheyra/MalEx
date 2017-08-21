# Install

## step by step

1. Go to the root of the directory
2. execute command `virtualenv -p /path/to/python2 $some_name`
3. enter the virtualenv with `source $some_name/bin/activate`
4. execute command `pip2 install -r requirements.txt`
5. everything is working fine by now

## requirements

| package | usage | link |
| :---: | :---: | :---: |
| angr | reverse engineering framework | [angr](http://angr.io/)|
| angrutils | export visual representation of resources extracted by angr | [angrutils](https://github.com/axt/angr-utils)
| networkx | manipulation, study of structures and dynamics of complex networks also used by angr| [networkx](https://networkx.github.io/) |
| coloredlogs | fancy logger | [coloredlogs](https://coloredlogs.readthedocs.io/en/latest/)
