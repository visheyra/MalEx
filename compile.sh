#!/bin/bash

rm -rf public && mkdir public

echo "Creating gh-pages branch in ./public"
git -C public init
git -C public checkout -b gh-pages

cd malex-web
hugo
ls
ls public
cp public/* ../public -rf
rm -rf public
cd -
