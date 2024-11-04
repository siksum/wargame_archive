#!/bin/bash

while :
do
    su -c "exec socat TCP-LISTEN:5103,reuseaddr,fork EXEC:'/challenge/free_shell.py,stderr'" - challenge;
done