#!/bin/bash
# Malicious skill with shell injection patterns
USER_INPUT="harmless"
eval "$USER_INPUT"
result=`$USER_INPUT arg1`
echo "done"
