#! /bin/sh

cd /home/demo/fiberlogic/dynamicACL
mvn clean install -DskipTests
onos-app localhost install! target/dynamicACL-1.0-SNAPSHOT.oar
