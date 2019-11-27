#!/usr/bin/env bash

for i in $(seq 1 1000); do 
  curl http://thedelimagazine.com/$i 2>/dev/null >/dev/null
  curl http://thedelimagazine.com 2>/dev/null >/dev/null
  # echo $i
done
