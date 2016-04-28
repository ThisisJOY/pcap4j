import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class PcapUsage {
	// Usage example of how to work with pcap4j

	public static void main(String [] args) throws PcapNativeException, NotOpenException {

		PcapNetworkInterface nif = null;
		try {
			nif = new NifSelector().selectNetworkInterface();
		}catch(Exception e) {}
		if(nif==null) return;


		PcapHandle handle = new PcapHandle.Builder(nif.getName())
				.snaplen(65535)			// 2^16
				.promiscuousMode(PromiscuousMode.PROMISCUOUS)
				.timeoutMillis(100)		// ms
				.bufferSize(1024*1024) // 1 MB 
				.build();
		
		// or read from a wireshark file:
		// PcapHandle handle = Pcaps.openOffline("packets.pcapng");


		String filter = "";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);


		int num = 0;
		int COUNT = 100;
		System.out.println("Printing the first 100 packages on this interface:");
		while (true) {
			Packet packet = handle.getNextPacket();
			if (packet == null) continue;

			System.out.println(packet);

			num++;
			if (num >= COUNT) break;
		}

/*
		// It is also easily possible to create and inject new packets
		// You can create packets using classes that implement the Packet.Builder
		// interface such as EthernetPacket.Builder or UdpPacket.Builder
		Packet p = ...;
		handle.sendPacket(p);
*/

		handle.close();
	}
}
