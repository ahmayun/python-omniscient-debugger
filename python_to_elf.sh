#!/bin/bash

TARGET_NAME=$1
rm cython/$TARGET_NAME.c bin/$TARGET_NAME &> /dev/null

cython3 -3 --line-directives targets/$TARGET_NAME.py --embed
mv targets/$TARGET_NAME.c cython
gcc cython/$TARGET_NAME.c -o bin/test_program $(python2-config --cflags --ldflags)
