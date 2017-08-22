#!/bin/bash

rm -rf public && mkdir public
cd malex-web
hugo
ls
ls public
cp public/* ../public -rf
rm -rf public
cd ../public
git add --all
git commit -m "automatic build from the CI to build the site"
git push upstream gh-pages
