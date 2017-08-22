#!/usr/bin/env sh

cd malex-web
hugo
cd -
cp malex-web/public/* docs/ -rf
