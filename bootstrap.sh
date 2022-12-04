#!/usr/bin/env bash

mkdir -p public

for f in samples/*.tar.gz
do
  echo $f
  tar xvzf $f -C public/
done