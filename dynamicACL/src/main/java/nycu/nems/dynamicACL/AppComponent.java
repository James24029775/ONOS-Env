/*
 * Copyright 2023-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.nems.dynamicACL;

import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.Link;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.Path;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import java.util.concurrent.ExecutorService;

import org.onosproject.event.Event;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.FLOW_PRIORITY;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.FLOW_PRIORITY_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.FLOW_TIMEOUT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.FLOW_TIMEOUT_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.IGNORE_IPV4_MCAST_PACKETS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.IGNORE_IPV4_MCAST_PACKETS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.IPV6_FORWARDING;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.IPV6_FORWARDING_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_DST_MAC_ONLY;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_DST_MAC_ONLY_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_ICMP_FIELDS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_ICMP_FIELDS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV4_ADDRESS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV4_ADDRESS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV4_DSCP;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV4_DSCP_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV6_ADDRESS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV6_ADDRESS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV6_FLOW_LABEL;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_IPV6_FLOW_LABEL_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_TCP_UDP_PORTS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_TCP_UDP_PORTS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_VLAN_ID;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.MATCH_VLAN_ID_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.PACKET_OUT_OFPP_TABLE;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.PACKET_OUT_OFPP_TABLE_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.PACKET_OUT_ONLY;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.PACKET_OUT_ONLY_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.RECORD_METRICS;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.RECORD_METRICS_DEFAULT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.INHERIT_FLOW_TREATMENT;
import static nycu.nems.dynamicACL.OsgiPropertyConstants.INHERIT_FLOW_TREATMENT_DEFAULT;
// My imports
import java.io.*;
import java.util.*;
import org.onosproject.net.flowobjective.*;
import org.onlab.packet.*;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;
import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, service = { AppComponent.class }, property = {
        "someProperty=Some Default String Value",
})
public class AppComponent {
    /** Some configurable property. */
    private final Logger log = LoggerFactory.getLogger(getClass());
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    /** My variables. */
    public static final int DEFAULT_IPV4_PRIORITY = 1;
    public static final int DEFAULT_PRIORITY = 30;
    public static final int DEFAULT_TIMEOUT = 30;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    /**
     ******************************** from reactive forwarding APP************************************
     */

    private EventuallyConsistentMap<MacAddress, ReactiveForwardMetrics> metrics;

    private ExecutorService blackHoleExecutor;

    private final TopologyListener topologyListener = new InternalTopologyListener();

    /** Enable matching IPv6 Addresses; default is false. */
    private boolean matchIpv6Address = MATCH_IPV6_ADDRESS_DEFAULT;

    /** Enable matching IPv6 FlowLabel; default is false. */
    private boolean matchIpv6FlowLabel = MATCH_IPV6_FLOW_LABEL_DEFAULT;

    /** Configure Flow Priority for installed flow rules; default is 10. */
    private int flowPriority = FLOW_PRIORITY_DEFAULT;

    /**
     * Enable first packet forwarding using OFPP_TABLE port instead of PacketOut
     * with actual port; default is false.
     */
    private boolean packetOutOfppTable = PACKET_OUT_OFPP_TABLE_DEFAULT;

    /** Configure Flow Timeout for installed flow rules; default is 10 sec. */
    private int flowTimeout = FLOW_TIMEOUT_DEFAULT;

    /**
     * Enable use of builder from packet context to define flow treatment; default
     * is false.
     */
    private boolean inheritFlowTreatment = INHERIT_FLOW_TREATMENT_DEFAULT;

    /** Enable matching ICMPv4 and ICMPv6 fields; default is false. */
    private boolean matchIcmpFields = MATCH_ICMP_FIELDS_DEFAULT;

    /** Enable matching TCP/UDP ports; default is false. */
    private boolean matchTcpUdpPorts = MATCH_TCP_UDP_PORTS_DEFAULT;

    /** Enable matching IPv4 DSCP and ECN; default is false. */
    private boolean matchIpv4Dscp = MATCH_IPV4_DSCP_DEFAULT;

    /** Enable matching IPv4 Addresses; default is false. */
    private boolean matchIpv4Address = MATCH_IPV4_ADDRESS_DEFAULT;

    /** Enable matching Vlan ID; default is false. */
    private boolean matchVlanId = MATCH_VLAN_ID_DEFAULT;

    /** Enable matching Dst Mac Only; default is false. */
    private boolean matchDstMacOnly = MATCH_DST_MAC_ONLY_DEFAULT;

    /** Enable packet-out only forwarding; default is false. */
    private boolean packetOutOnly = PACKET_OUT_ONLY_DEFAULT;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    /** Enable IPv6 forwarding; default is false. */
    private boolean ipv6Forwarding = IPV6_FORWARDING_DEFAULT;

    /** Enable record metrics for reactive forwarding. */
    private boolean recordMetrics = RECORD_METRICS_DEFAULT;

    /** Ignore (do not forward) IPv4 multicast packets; default is false. */
    private boolean ignoreIPv4Multicast = IGNORE_IPV4_MCAST_PACKETS_DEFAULT;

    private ApplicationId appId;

    Map<DeviceId, Map<MacAddress, PortNumber>> macTable = new HashMap<>();

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());

        appId = coreService.registerApplication("nycu.nems.dynamicACL");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        topologyService.addListener(topologyListener);
        requestIntercepts();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);

        withdrawIntercepts();
        packetService.removeProcessor(processor);
        topologyService.removeListener(topologyListener);
        processor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    /**
     * Whenever a packet goes into a controller, it will do the function.
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            // check if ethPkt is null
            if (ethPkt == null) {
                return;
            }

            MacAddress sourceMac = ethPkt.getSourceMAC();
            MacAddress destinationMac = ethPkt.getDestinationMAC();
            DeviceId switchId = pkt.receivedFrom().deviceId();
            PortNumber inPort = context.inPacket().receivedFrom().port();

            ReactiveForwardMetrics macMetrics = null;
            macMetrics = createCounter(sourceMac);
            inPacket(macMetrics);

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                droppedPacket(macMetrics);
                return;
            }

            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
                droppedPacket(macMetrics);
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(ethPkt.getVlanID()));

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                droppedPacket(macMetrics);
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ignoreIPv4Multicast && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }

            // test!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context, macMetrics);
                return;
            }

            // 如果發起packet-in的裝置與封包欲送達的裝置相同，就安裝flow rule
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                // 如果進、出的port是不同的才接受服務
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port(), macMetrics);
                }
                return;
            }

            // 否則，使用topologyService取得一堆可能抵達目的switch的路徑，
            Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                    pkt.receivedFrom().deviceId(),
                    dst.location().deviceId());
            if (paths.isEmpty()) {
                // 如果路徑為空，採用flood策略
                flood(context, macMetrics);
                return;
            }

            // 否則，pickForwardPathIfPossible從中挑選一條路徑，該路徑的入口的port和出口的port不應相同
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                // 若不存在這種條件的路徑，就flood
                log.warn("Don't know where to go from here {} for {} -> {}",
                        pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context, macMetrics);
                return;
            }

            // 否則，依照這個路徑安裝flow rule
            installRule(context, path.src().port(), macMetrics);
        }

    }

    private String queryRedis(String method, String arg1, String arg2) {
        try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec("python3 /dynamicACL/connect_redis.py");
            // Process proc = rt.exec("python3
            // /home/demo/fiberlogic/dynamicACL/connect_redis.py");
            OutputStream stdin = proc.getOutputStream();
            InputStream stdout = proc.getInputStream();
            String line;

            // Enter input
            if (arg2 == null) {
                arg2 = "";
            }
            line = method + " " + arg1 + " " + arg2 + "\n";
            stdin.write(line.getBytes());
            stdin.flush();

            // Get output
            BufferedReader brCleanUp = new BufferedReader(new InputStreamReader(stdout));
            if ((line = brCleanUp.readLine()) != null) {
                brCleanUp.close();
                return line;
            }
        } catch (Exception e) {
            log.info("[Error]");
        }
        return "BBBBBBBBBB";
    }

    private void updateMacTable(DeviceId switchId, MacAddress sourceMac, PortNumber inPort) {
        macTable.computeIfAbsent(switchId, k -> new HashMap<>()).put(sourceMac, inPort);
    }

    // ! myselffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // // Sends a packet out the specified port.
    // private void packetOut(PacketContext context, PortNumber portNumber) {
    // context.treatmentBuilder().setOutput(portNumber);
    // context.send();
    // }

    // Install a flow rule to a switch.
    private void installL4FlowRule(PacketContext context, PortNumber toPort) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        PortNumber inPort = context.inPacket().receivedFrom().port();

        if (ethPkt == null) {
            return;
        }

        // parse L2 header
        String sourceMac = ethPkt.getSourceMAC().toString();
        String destinationMac = ethPkt.getDestinationMAC().toString();
        DeviceId switchId = pkt.receivedFrom().deviceId(); // The one sending pktIn to the controller.

        // parse L3 header
        IPv4 ipPacket = (IPv4) ethPkt.getPayload();
        String srcIp = Ip4Address.valueOf(ipPacket.getSourceAddress()).toString();
        String dstIp = Ip4Address.valueOf(ipPacket.getDestinationAddress()).toString();

        // parse L4 header
        String sPort = null, dPort = null;
        if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
            TCP tcp = (TCP) ipPacket.getPayload();
            sPort = Integer.valueOf(tcp.getSourcePort()).toString();
            dPort = Integer.valueOf(tcp.getDestinationPort()).toString();
        } else if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
            UDP udp = (UDP) ipPacket.getPayload();
            sPort = Integer.valueOf(udp.getSourcePort()).toString();
            dPort = Integer.valueOf(udp.getDestinationPort()).toString();
        }
        int srcPort = Integer.parseUnsignedInt(sPort);
        int dstPort = Integer.parseUnsignedInt(dPort);

        /**
         * FlowRuleService
         */
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        TrafficTreatment treatment;
        FlowRule flowRule;

        if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
            // A to B
            selector.matchEthSrc(MacAddress.valueOf(sourceMac))
                    .matchEthDst(MacAddress.valueOf(destinationMac))
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                    .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(TpPort.tpPort(srcPort))
                    .matchTcpDst(TpPort.tpPort(dstPort));

            treatment = DefaultTrafficTreatment.builder().setOutput(toPort).build();

            flowRule = DefaultFlowRule.builder()
                    .forDevice(switchId)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(DEFAULT_PRIORITY)
                    .makeTemporary(DEFAULT_TIMEOUT)
                    .fromApp(appId)
                    .build();
            flowRuleService.applyFlowRules(flowRule);

            // B to A
            selector.matchEthSrc(MacAddress.valueOf(destinationMac))
                    .matchEthDst(MacAddress.valueOf(sourceMac))
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                    .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(TpPort.tpPort(dstPort))
                    .matchTcpDst(TpPort.tpPort(srcPort));

            treatment = DefaultTrafficTreatment.builder().setOutput(inPort).build();

            flowRule = DefaultFlowRule.builder()
                    .forDevice(switchId)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(DEFAULT_PRIORITY)
                    .makeTemporary(DEFAULT_TIMEOUT)
                    .fromApp(appId)
                    .build();
            flowRuleService.applyFlowRules(flowRule);

        } else if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
            // A to B
            selector.matchEthSrc(MacAddress.valueOf(sourceMac))
                    .matchEthDst(MacAddress.valueOf(destinationMac))
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                    .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchUdpSrc(TpPort.tpPort(srcPort))
                    .matchUdpDst(TpPort.tpPort(dstPort));

            treatment = DefaultTrafficTreatment.builder().setOutput(toPort).build();

            flowRule = DefaultFlowRule.builder()
                    .forDevice(switchId)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(DEFAULT_PRIORITY)
                    .makeTemporary(DEFAULT_TIMEOUT)
                    .fromApp(appId)
                    .build();
            flowRuleService.applyFlowRules(flowRule);

            // B to A
            selector.matchEthSrc(MacAddress.valueOf(destinationMac))
                    .matchEthDst(MacAddress.valueOf(sourceMac))
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                    .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchUdpSrc(TpPort.tpPort(dstPort))
                    .matchUdpDst(TpPort.tpPort(srcPort));

            treatment = DefaultTrafficTreatment.builder().setOutput(inPort).build();

            flowRule = DefaultFlowRule.builder()
                    .forDevice(switchId)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(DEFAULT_PRIORITY)
                    .makeTemporary(DEFAULT_TIMEOUT)
                    .fromApp(appId)
                    .build();
            flowRuleService.applyFlowRules(flowRule);
        }
    }

    // Install a flow rule to a switch.
    private void installL3FlowRule(PacketContext context, PortNumber toPort) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        PortNumber inPort = context.inPacket().receivedFrom().port();

        if (ethPkt == null) {
            return;
        }

        // parse L2 header
        String sourceMac = ethPkt.getSourceMAC().toString();
        String destinationMac = ethPkt.getDestinationMAC().toString();
        DeviceId switchId = pkt.receivedFrom().deviceId(); // The one sending pktIn to the controller.

        // parse L3 header
        IPv4 ipPacket = (IPv4) ethPkt.getPayload();
        String srcIp = Ip4Address.valueOf(ipPacket.getSourceAddress()).toString();
        String dstIp = Ip4Address.valueOf(ipPacket.getDestinationAddress()).toString();

        /**
         * FlowRuleService
         */
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        TrafficTreatment treatment;
        FlowRule flowRule;

        // A to B
        selector.matchEthSrc(MacAddress.valueOf(sourceMac))
                .matchEthDst(MacAddress.valueOf(destinationMac))
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                .matchIPProtocol(IPv4.PROTOCOL_ICMP);

        treatment = DefaultTrafficTreatment.builder().setOutput(toPort).build();
        flowRule = DefaultFlowRule.builder()
                .forDevice(switchId)
                .withSelector(selector.build())
                .withTreatment(treatment)
                .withPriority(DEFAULT_PRIORITY)
                .makeTemporary(DEFAULT_TIMEOUT)
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(flowRule);

        // B to A
        selector.matchEthSrc(MacAddress.valueOf(destinationMac))
                .matchEthDst(MacAddress.valueOf(sourceMac))
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(dstIp), 32))
                .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(srcIp), 32))
                .matchIPProtocol(IPv4.PROTOCOL_ICMP);

        treatment = DefaultTrafficTreatment.builder().setOutput(inPort).build();
        flowRule = DefaultFlowRule.builder()
                .forDevice(switchId)
                .withSelector(selector.build())
                .withTreatment(treatment)
                .withPriority(DEFAULT_PRIORITY)
                .makeTemporary(DEFAULT_TIMEOUT)
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }

    // Install a flow rule to a switch.
    private void installL2FlowRule(PacketContext context, PortNumber portNumber) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();

        if (ethPkt == null) {
            return;
        }

        MacAddress sourceMac = ethPkt.getSourceMAC();
        MacAddress destinationMac = ethPkt.getDestinationMAC();
        DeviceId switchId = pkt.receivedFrom().deviceId(); // The one sending pktIn to the controller.

        /**
         * FlowRuleService
         */
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        TrafficTreatment treatment;
        selector.matchEthSrc(MacAddress.valueOf(sourceMac.toString()))
                .matchEthDst(MacAddress.valueOf(destinationMac.toString()))
                .matchEthType(Ethernet.TYPE_ARP);
        treatment = DefaultTrafficTreatment.builder().setOutput(portNumber).build();
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(switchId)
                .withSelector(selector.build())
                .withTreatment(treatment)
                .withPriority(DEFAULT_PRIORITY)
                .makeTemporary(DEFAULT_TIMEOUT)
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     ******************************** from reactive forwarding APP************************************
     */

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    private void inPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementInPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    private ReactiveForwardMetrics createCounter(MacAddress macAddress) {
        ReactiveForwardMetrics macMetrics = null;
        if (recordMetrics) {
            macMetrics = metrics.compute(macAddress, (key, existingValue) -> {
                if (existingValue == null) {
                    return new ReactiveForwardMetrics(0L, 0L, 0L, 0L, macAddress);
                } else {
                    return existingValue;
                }
            });
        }
        return macMetrics;
    }

    private void droppedPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementDroppedPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context, ReactiveForwardMetrics macMetrics) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD, macMetrics);
        } else {
            context.block();
        }
    }

    private void replyPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incremnetReplyPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber, ReactiveForwardMetrics macMetrics) {
        replyPacket(macMetrics);
        context.treatmentBuilder().setOutput(portNumber);
        context.send();

    }

    private void forwardPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementForwardedPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {
            List<Event> reasons = event.reasons();
            if (reasons != null) {
                reasons.forEach(re -> {
                    if (re instanceof LinkEvent) {
                        LinkEvent le = (LinkEvent) re;
                        if (le.type() == LinkEvent.Type.LINK_REMOVED && blackHoleExecutor != null) {
                            blackHoleExecutor.submit(() -> fixBlackhole(le.subject().src()));
                        }
                    }
                });
            }
        }
    }

    private void fixBlackhole(ConnectPoint egress) {
        Set<FlowEntry> rules = getFlowRulesFrom(egress);
        Set<SrcDstPair> pairs = findSrcDstPairs(rules);

        Map<DeviceId, Set<Path>> srcPaths = new HashMap<>();

        for (SrcDstPair sd : pairs) {
            // get the edge deviceID for the src host
            Host srcHost = hostService.getHost(HostId.hostId(sd.src));
            Host dstHost = hostService.getHost(HostId.hostId(sd.dst));
            if (srcHost != null && dstHost != null) {
                DeviceId srcId = srcHost.location().deviceId();
                DeviceId dstId = dstHost.location().deviceId();
                log.trace("SRC ID is {}, DST ID is {}", srcId, dstId);

                cleanFlowRules(sd, egress.deviceId());

                Set<Path> shortestPaths = srcPaths.get(srcId);
                if (shortestPaths == null) {
                    shortestPaths = topologyService.getPaths(topologyService.currentTopology(),
                            egress.deviceId(), srcId);
                    srcPaths.put(srcId, shortestPaths);
                }
                backTrackBadNodes(shortestPaths, dstId, sd);
            }
        }
    }

    private Set<FlowEntry> getFlowRulesFrom(ConnectPoint egress) {
        ImmutableSet.Builder<FlowEntry> builder = ImmutableSet.builder();
        flowRuleService.getFlowEntries(egress.deviceId()).forEach(r -> {
            if (r.appId() == appId.id()) {
                r.treatment().allInstructions().forEach(i -> {
                    if (i.type() == Instruction.Type.OUTPUT) {
                        if (((Instructions.OutputInstruction) i).port().equals(egress.port())) {
                            builder.add(r);
                        }
                    }
                });
            }
        });

        return builder.build();
    }

    // Wrapper class for a source and destination pair of MAC addresses
    private final class SrcDstPair {
        final MacAddress src;
        final MacAddress dst;

        private SrcDstPair(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SrcDstPair that = (SrcDstPair) o;
            return Objects.equals(src, that.src) &&
                    Objects.equals(dst, that.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }
    }

    // Returns a set of src/dst MAC pairs extracted from the specified set of flow
    // entries
    private Set<SrcDstPair> findSrcDstPairs(Set<FlowEntry> rules) {
        ImmutableSet.Builder<SrcDstPair> builder = ImmutableSet.builder();
        for (FlowEntry r : rules) {
            MacAddress src = null, dst = null;
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.ETH_DST) {
                    dst = ((EthCriterion) cr).mac();
                } else if (cr.type() == Criterion.Type.ETH_SRC) {
                    src = ((EthCriterion) cr).mac();
                }
            }
            builder.add(new SrcDstPair(src, dst));
        }
        return builder.build();
    }

    // Removes flow rules off specified device with specific SrcDstPair
    private void cleanFlowRules(SrcDstPair pair, DeviceId id) {
        log.trace("Searching for flow rules to remove from: {}", id);
        log.trace("Removing flows w/ SRC={}, DST={}", pair.src, pair.dst);
        for (FlowEntry r : flowRuleService.getFlowEntries(id)) {
            boolean matchesSrc = false, matchesDst = false;
            for (Instruction i : r.treatment().allInstructions()) {
                if (i.type() == Instruction.Type.OUTPUT) {
                    // if the flow has matching src and dst
                    for (Criterion cr : r.selector().criteria()) {
                        if (cr.type() == Criterion.Type.ETH_DST) {
                            if (((EthCriterion) cr).mac().equals(pair.dst)) {
                                matchesDst = true;
                            }
                        } else if (cr.type() == Criterion.Type.ETH_SRC) {
                            if (((EthCriterion) cr).mac().equals(pair.src)) {
                                matchesSrc = true;
                            }
                        }
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: {}", id);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }

    }

    // Backtracks from link down event to remove flows that lead to blackhole
    private void backTrackBadNodes(Set<Path> shortestPaths, DeviceId dstId, SrcDstPair sd) {
        for (Path p : shortestPaths) {
            List<Link> pathLinks = p.links();
            for (int i = 0; i < pathLinks.size(); i = i + 1) {
                Link curLink = pathLinks.get(i);
                DeviceId curDevice = curLink.src().deviceId();

                // skipping the first link because this link's src has already been pruned
                // beforehand
                if (i != 0) {
                    cleanFlowRules(sd, curDevice);
                }

                Set<Path> pathsFromCurDevice = topologyService.getPaths(topologyService.currentTopology(),
                        curDevice, dstId);
                if (pickForwardPathIfPossible(pathsFromCurDevice, curLink.src().port()) != null) {
                    break;
                } else {
                    if (i + 1 == pathLinks.size()) {
                        cleanFlowRules(sd, curLink.dst().deviceId());
                    }
                }
            }
        }
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber, ReactiveForwardMetrics macMetrics) {
        boolean L3aclFlg = false, L4aclFlg = false, mecPrefixFlg = false;

        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // If PacketOutOnly or ARP packet than forward directly to output port
        if (packetOutOnly || inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber, macMetrics);
            return;
        }

        //
        // If matchDstMacOnly
        // Create flows matching dstMac only
        // Else
        // Create flows with default matching and include configured fields
        //
        if (matchDstMacOnly) {
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                    .matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            if (matchVlanId && inPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                selectorBuilder.matchVlanId(VlanId.vlanId(inPkt.getVlanID()));
            }

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                // parse IPv4 header
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Address srcIpObj = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                Ip4Address dstIpObj = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
                String srcIp = srcIpObj.toString();
                String dstIp = dstIpObj.toString();
                log.info("");
                log.info("The current IP pair: {} <-> {}", srcIp, dstIp);

                // check whether source IP is from MEC prefix
                Ip4Prefix mecPrefix = Ip4Prefix.valueOf("192.168.100.0/24");
                if (mecPrefix.contains(srcIpObj)) {
                    log.info("{} is in MEC Prefix.", srcIp);
                    mecPrefixFlg = true;
                } else {
                    mecPrefixFlg = false;
                }

                if (!mecPrefixFlg) {
                    // check ACL for source IP
                    if (queryRedis("hvals", srcIp, null).equals("True")) {
                        log.info("{} is allowed for L3 ACL.", srcIp);
                        L3aclFlg = true;
                    } else {
                        log.info("{} is not allowed for L3 ACL.", srcIp);
                        L3aclFlg = false;
                    }

                    if (L3aclFlg) {
                        Ip4Prefix matchIp4SrcPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);
                        Ip4Prefix matchIp4DstPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);
                        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                                .matchIPSrc(matchIp4SrcPrefix)
                                .matchIPDst(matchIp4DstPrefix);
                    }

                    // if (matchIpv4Dscp) {
                    // byte dscp = ipv4Packet.getDscp();
                    // byte ecn = ipv4Packet.getEcn();
                    // selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                    // }

                    // check ACL for TCP or UDP
                    String dstPort = null;
                    if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                        dstPort = Integer.valueOf(tcpPacket.getDestinationPort()).toString();
                    }
                    if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                        UDP udpPacket = (UDP) ipv4Packet.getPayload();
                        dstPort = Integer.valueOf(udpPacket.getDestinationPort()).toString();
                    }

                    String hashKey = dstIp + ":" + dstPort;
                    log.info("L3SHIT: {}", queryRedis("hvals", srcIp, null));
                    log.info("L4SHIT: {}", queryRedis("hget", srcIp, hashKey));
                    log.info("Key: {}", hashKey);
                    if (!mecPrefixFlg) {
                        if (queryRedis("hget", srcIp, hashKey).equals("True")) {
                            log.info("{} is allowed for L4 ACL.", srcIp);
                            L4aclFlg = true;
                        } else {
                            log.info("{} is not allowed for L4 ACL.", srcIp);
                            L4aclFlg = false;
                        }
                    }

                    if (L4aclFlg) {
                        if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                            selectorBuilder.matchIPProtocol(ipv4Protocol)
                                    .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                        }
                        if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                            UDP udpPacket = (UDP) ipv4Packet.getPayload();
                            selectorBuilder.matchIPProtocol(ipv4Protocol)
                                    .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                        }
                    }
                }
            }
        }

        if (mecPrefixFlg || (L3aclFlg && L4aclFlg)) {
            TrafficTreatment treatment;
            if (inheritFlowTreatment) {
                treatment = context.treatmentBuilder()
                        .setOutput(portNumber)
                        .build();
            } else {
                treatment = DefaultTrafficTreatment.builder()
                        .setOutput(portNumber)
                        .build();
            }

            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(flowPriority)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(flowTimeout)
                    .add();

            flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                    forwardingObjective);
            forwardPacket(macMetrics);
            //
            // If packetOutOfppTable
            // Send packet back to the OpenFlow pipeline to match installed flow
            // Else
            // Send packet direction on the appropriate port
            //
            if (packetOutOfppTable) {
                packetOut(context, PortNumber.TABLE, macMetrics);
            } else {
                packetOut(context, portNumber, macMetrics);
            }
        }
    }
}
