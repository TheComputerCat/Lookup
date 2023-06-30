#!/bin/bash

set -e

VOLUME=$1

cd $VOLUME
python -m unittest discover src/tests/

