#!/usr/bin/env bash

ifconfig

cp keystore.jks target
cd target
java -jar BouncyCastleTLS-1.58-1.0.jar
