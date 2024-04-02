
FROM ubuntu:22.04

COPY ./env_setup /env_setup
COPY ./dynamicACL /dynamicACL

ENV BAZELISK_VERSION='1.12.0'
ENV ONOS_DIR="${HOME}/onos"
ENV ONOS_VERSION='2.7.0'
ENV ONOS_ROOT=${ONOS_DIR}

WORKDIR /
RUN /env_setup/env_setup.sh
RUN /env_setup/install_jdk.sh
RUN /env_setup/install_maven.sh

RUN cd /dynamicACL
RUN mvn clean install -DskipTests
RUN onos-app localhost install! target/dynamicACL-1.0-SNAPSHOT.oar

CMD [ "sleep inifinty" ]