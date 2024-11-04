#!/bin/bash

while :
do
    exec socat TCP-LISTEN:5101,reuseaddr,fork EXEC:'/app/timelimit,stderr'
done