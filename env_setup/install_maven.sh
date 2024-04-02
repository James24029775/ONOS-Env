#! /bin/sh

export ONOS_POM_VERSION=2.7.0

cd $ONOS_ROOT/tools/package/archetypes
mvn clean install -DskipTests
