
public void process(PacketContext context) {

    /** Update ONOS mac table */
    log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.", switchId, sourceMac,
            inPort);
    updateMacTable(switchId, sourceMac, inPort);

    /** If Query is hit, install a flow rule, else flood the packet */
    Boolean ifHitTable = macTable.containsKey(switchId)
            && macTable.get(switchId).containsKey(destinationMac);

    // for (Map.Entry<DeviceId, Map<MacAddress, PortNumber>> entry : macTable.entrySet()) {
    //     DeviceId deviceId = entry.getKey();
    //     Map<MacAddress, PortNumber> innerMap = entry.getValue();

    //     log.info("Device ID: {}", deviceId);

    //     for (Map.Entry<MacAddress, PortNumber> innerEntry : innerMap.entrySet()) {
    //         MacAddress macAddress = innerEntry.getKey();
    //         PortNumber portNumber = innerEntry.getValue();
    //         log.info(" MAC Address: {}, Port Number: {}", macAddress, portNumber);
    //     }
    // }
    if (ifHitTable) {

        // install flow rules based on ARP
        if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
            log.info("{}, {} are ARP packets, just let them pass", destinationMac,
                    switchId);
            PortNumber toPort = macTable.get(switchId).get(destinationMac);
            installL2FlowRule(context, toPort);
            packetOut(context, toPort);
            return;
        }

        // filter ip packets
        if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
            return;
        }

        // parse IPv4 header
        IPv4 ipPacket = (IPv4) ethPkt.getPayload();
        Ip4Address srcIpObj = Ip4Address.valueOf(ipPacket.getSourceAddress());
        Ip4Address dstIpObj = Ip4Address.valueOf(ipPacket.getDestinationAddress());
        String srcIp = srcIpObj.toString();
        String dstIp = dstIpObj.toString();

        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // // if srcIp is from MEC subnet, just let it go
        // Ip4Prefix mecSubnet = Ip4Prefix.valueOf("192.168.100.0/24");
        // log.info("The pairs IP are {}, {}.", srcIp, dstIp);
        // if (mecSubnet.contains(srcIpObj)) {
        //     log.info("{} is MEC IPs, just let it pass.", srcIp);
        //     PortNumber toPort = macTable.get(switchId).get(destinationMac);
        //     installL2FlowRule(context, toPort);
        //     packetOut(context, toPort);
        //     return;
        // }

        // check IPv4 ACL
        log.info("IPv4 ACL-> {}:{}", srcIp, queryRedis("hvals", srcIp, null));
        if (!queryRedis("hvals", srcIp, null).equals("True")) {
            log.info("{} does not allow to access MEC!", srcIp);
            return;
        }

        if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
            // install flow rules based on ICMP
            log.info("{}, {} are legal pairs by ICMP.", srcIp, dstIp);
            PortNumber toPort = macTable.get(switchId).get(destinationMac);
            installL3FlowRule(context, toPort);
            packetOut(context, toPort);
            return;
        } else {
            // install flow rules based on UDP, TCP
            String dstPort = null;
            if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcp = (TCP) ipPacket.getPayload();
                dstPort = Integer.valueOf(tcp.getDestinationPort()).toString();
            } else if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udp = (UDP) ipPacket.getPayload();
                dstPort = Integer.valueOf(udp.getDestinationPort()).toString();
            }

            // check UDP, TCP ACL
            String hashKey = dstIp + ":" + dstPort;
            log.info("L4 ACL-> {} want to access {}, and the result is {}.", srcIp,
                    hashKey,
                    queryRedis("hget", srcIp, hashKey));
            if (queryRedis("hget", srcIp, hashKey).equals("True")) {
                log.info("{}, {} are legal pairs by L4 protocols.", srcIp, dstIp);
                PortNumber toPort = macTable.get(switchId).get(destinationMac);
                installL4FlowRule(context, toPort);
                packetOut(context, toPort);
                return;
            } else {
                log.info("{} does not allow to access {}!", srcIp, hashKey);
            }
        }
    } else {
        log.info("MAC address `{}` is missed on `{}`. Flood the packet.",
                destinationMac, switchId);
        packetOut(context, PortNumber.FLOOD);
    }
}
