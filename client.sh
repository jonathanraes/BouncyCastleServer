#!/usr/bin/env bash

echo 10.0.1.30 website.com >> /etc/hosts # location of mitm

python3 attack.py &

sleep 5
curl -s --insecure --http0.9 https://website.com:8888

sleep 50
