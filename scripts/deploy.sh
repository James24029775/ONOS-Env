#! /bin/sh

# initialization
sudo ovs-vsctl del-br OVS
docker compose down

# build topology
docker compose up -d

# create ovs
sudo ovs-vsctl add-br OVS -- set bridge OVS protocols=OpenFlow14
# sudo ovs-vsctl add-br OVS -- set bridge OVS datapath_type=netdev protocols=OpenFlow13

# let routers connect to OVS
sudo ovs-docker add-port OVS OVSR1 R1 --ipaddress=192.168.100.2/16
sudo ovs-docker add-port OVS OVSR2 R2 --ipaddress=192.168.200.3/16

# set controller
sudo ovs-vsctl set-controller OVS tcp:127.0.0.1:6653
