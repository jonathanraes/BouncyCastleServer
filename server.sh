#!/usr/bin/env bash

ifconfig

cp keystore.jks target
cd target
java -cp BouncyCastleTLS.jar de.rub.nds.bc.BouncyCastleTLSServer #java -jar BouncyCastleTLS.jar # BouncyCastleTLS-1.58-1.0.jar
