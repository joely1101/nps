#!/bin/bash
set -e
rm -rf nps
mkdir -p nps/web
cp ../nps nps/
cp -a ../conf nps/
cd nps/conf
ls *.json | xargs -i sh -c 'echo "" > {}'
cd -
cp -a ../web/{"static","views"} nps/web/
docker build --no-cache -t nps_jumper .
docker images nps_jumper

