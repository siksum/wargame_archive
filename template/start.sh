#!/bin/bash

# nc - python
while :
do
    su -c "exec socat TCP-LISTEN:5103,reuseaddr,fork EXEC:'/challenge/free_shell.py,stderr'" - challenge;
done

# nc - binary
while :
do
    exec socat TCP-LISTEN:5101,reuseaddr,fork EXEC:'/app/timelimit,stderr'
done

# ssh 
mkdir /var/run/sshd
/usr/sbin/sshd -D
/etc/init.d/ssh start