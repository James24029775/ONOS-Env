package nycu.nems.dynamicACL;

import org.onlab.packet.MacAddress;
import static com.google.common.base.MoreObjects.toStringHelper;

/**
 * Sample reactive forwarding application.
 */
public class ReactiveForwardMetrics {
    private Long replyPacket = null;
    private Long inPacket = null;
    private Long droppedPacket = null;
    private Long forwardedPacket = null;
    private MacAddress macAddress;

    ReactiveForwardMetrics(Long replyPacket, Long inPacket, Long droppedPacket,
                           Long forwardedPacket, MacAddress macAddress) {
        this.replyPacket = replyPacket;
        this.inPacket = inPacket;
        this.droppedPacket = droppedPacket;
        this.forwardedPacket = forwardedPacket;
        this.macAddress = macAddress;
    }

    public void incremnetReplyPacket() {
        replyPacket++;

    }

    public void incrementInPacket() {
        inPacket++;
    }

    public void incrementDroppedPacket() {
        droppedPacket++;
    }

    public void incrementForwardedPacket() {
        forwardedPacket++;
    }

    public MacAddress getMacAddress() {
        return macAddress;
    }

    @Override
    public String toString() {
        return toStringHelper(this)
            .add("inpktCounter ", inPacket)
            .add("replypktCounter ", replyPacket)
            .add("forwardpktCounter ", forwardedPacket)
            .add("droppktCounter ", droppedPacket).toString();
    }
}
