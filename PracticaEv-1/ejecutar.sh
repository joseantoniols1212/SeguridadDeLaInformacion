#!/bin/bash

fuser -k 8080/tcp
fuser -k 8081/tcp
fuser -k 8082/tcp

sleep 1

python3 ttp.py &

sleep 1

python3 alice.py &

sleep 1

python3 bob.py
