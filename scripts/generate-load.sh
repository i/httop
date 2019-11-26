#!/usr/bin/env bash

for i in $(seq 1 1000); do 
  curl http://thedelimagazine.com/foo  
  echo $i
done
