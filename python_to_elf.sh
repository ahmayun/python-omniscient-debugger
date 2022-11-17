#!/bin/bash

TARGET_NAME=$1
rm bin/$TARGET_NAME &> /dev/null
cython3 -3 --line-directives targets/$TARGET_NAME.py --embed && gcc cython/$TARGET_NAME.c -o bin/test_program $(python2-config --cflags --ldflags)
