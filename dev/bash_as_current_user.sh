#!/bin/bash

set -e

CURR_USER_UID=$1
CURR_USER_GID=$2
VOLUME=$3

mkdir -p /home/user

addgroup -g $CURR_USER_GID grp
adduser -D -h /home/user -u $CURR_USER_UID -G grp user

echo "cd $VOLUME" >> /home/user/.profile

su - user
