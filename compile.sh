#!/bin/bash

rm -rf docs && mkdir docs
malex-web/binaries/hugo -s "malex-web"
