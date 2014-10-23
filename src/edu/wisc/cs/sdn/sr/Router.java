package edu.wisc.cs.sdn.sr;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import edu.wisc.cs.sdn.sr.vns.VNSComm;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Router 
{
	/** User under which the router is running */
	private String user;
	
	/** Hostname for the router */
	private String host;
	
	/** Template name for the router; null if no template */
	private String template;
	
	/** Topology ID for the router */
	private short topo;
	
	/** List of the router's interfaces; maps interface name's to interfaces */
	private Map<String,Iface> interfaces;
	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/** PCAP dump file for logging all packets sent/received by the router;
	 *  null if packets should not be logged */
	private DumpFile logfile;
	
	/** Virtual Network Simulator communication manager for the router */
	private VNSComm vnsComm;

    /** RIP subsystem */
    private RIP rip;
	
	/**
	 * Creates a router for a specific topology, host, and user.
	 * @param topo topology ID for the router
	 * @param host hostname for the router
	 * @param user user under which the router is running
	 * @param template template name for the router; null if no template
	 */
	public Router(short topo, String host, String user, String template)
	{
		this.topo = topo;
		this.host = host;
		this.setUser(user);
		this.template = template;
		this.logfile = null;
		this.interfaces = new HashMap<String,Iface>();
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache(this);
		this.vnsComm = null;
        this.rip = new RIP(this);
	}
	
	public void init()
	{ this.rip.init(); }
	
	/**
	 * @param logfile PCAP dump file for logging all packets sent/received by 
	 * 		  the router; null if packets should not be logged
	 */
	public void setLogFile(DumpFile logfile)
	{ this.logfile = logfile; }
	
	/**
	 * @return PCAP dump file for logging all packets sent/received by the
	 *         router; null if packets should not be logged
	 */
	public DumpFile getLogFile()
	{ return this.logfile; }
	
	/**
	 * @param template template name for the router; null if no template
	 */
	public void setTemplate(String template)
	{ this.template = template; }
	
	/**
	 * @return template template name for the router; null if no template
	 */
	public String getTemplate()
	{ return this.template; }
		
	/**
	 * @param user user under which the router is running; if null, use current 
	 *        system user
	 */
	public void setUser(String user)
	{
		if (null == user)
		{ this.user = System.getProperty("user.name"); }
		else
		{ this.user = user; }
	}
	
	/**
	 * @return user under which the router is running
	 */
	public String getUser()
	{ return this.user; }
	
	/**
	 * @return hostname for the router
	 */
	public String getHost()
	{ return this.host; }
	
	/**
	 * @return topology ID for the router
	 */
	public short getTopo()
	{ return this.topo; }
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * @return list of the router's interfaces; maps interface name's to
	 * 	       interfaces
	 */
	public Map<String,Iface> getInterfaces()
	{ return this.interfaces; }
	
	/**
	 * @param vnsComm Virtual Network System communication manager for the router
	 */
	public void setVNSComm(VNSComm vnsComm)
	{ this.vnsComm = vnsComm; }
	
	/**
	 * Close the PCAP dump file for the router, if logging is enabled.
	 */
	public void destroy()
	{
		if (logfile != null)
		{ this.logfile.close(); }
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loading routing table");
		System.out.println("---------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("---------------------------------------------");
	}
	
	/**
	 * Add an interface to the router.
	 * @param ifaceName the name of the interface
	 */
	public Iface addInterface(String ifaceName)
	{
		Iface iface = new Iface(ifaceName);
		this.interfaces.put(ifaceName, iface);
		return iface;
	}
	
	/**
	 * Gets an interface on the router by the interface's name.
	 * @param ifaceName name of the desired interface
	 * @return requested interface; null if no interface with the given name 
	 * 		   exists
	 */
	public Iface getInterface(String ifaceName)
	{ return this.interfaces.get(ifaceName); }
	
	/**
	 * Send an Ethernet packet out a specific interface.
	 * @param etherPacket an Ethernet packet with all fields, encapsulated
	 * 		  headers, and payloads completed
	 * @param iface interface on which to send the packet
	 * @return true if the packet was sent successfully, otherwise false
	 */
	public boolean sendPacket(Ethernet etherPacket, Iface iface)
	{ 	
		return this.vnsComm.sendPacket(etherPacket, iface.getName()); 	
	}
	
	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		/********************************************************************/

		// Case 1: packet is of type ARP
		if (etherPacket.getEtherType() == Ethernet.TYPE_ARP) {	
			
			System.out.println("Received a ARP packet.");
			handleArpPacket(etherPacket, inIface);	
			
		// Case 2: packet is of type IP 
		} else if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
			
			System.out.println("Received a IPv4 packet.");
						
			handleIpPacket(etherPacket, inIface);

			return;
					
		} else {
			// Case 3: packet is of other type
			// TODO: send back error message
			
		}
		

	}
	
	/**
	 * Handle an ARP packet received on a specific interface.
	 * @param etherPacket the complete ARP packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }
		
		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();
		
		/* All code below was changed by Denis. Basically, when the other host send an ARP reply,
		 *  some fields are inverted (source by target, for example).
		 * 
		 */
		
		int targetIp = ByteBuffer.wrap(
				arpPacket.getTargetProtocolAddress()).getInt();
		
		int sourceIp = ByteBuffer.wrap(
				arpPacket.getSenderProtocolAddress()).getInt();
		
		
		switch(arpPacket.getOpCode())
		{
		case ARP.OP_REQUEST:
			
			System.out.println("Received a ARP request.");
			
			// Check if request is for one of my interfaces
			if (targetIp == inIface.getIpAddress())
			{ 
				// If the destination of the ARP reply is this router, add the information about the sender in the ArpCache.
				
				MACAddress sourceMac = MACAddress.valueOf(ByteBuffer.wrap(arpPacket.getSenderHardwareAddress()).array());
				
				this.arpCache.insert(sourceMac, sourceIp);			
				
				this.arpCache.sendArpReply(etherPacket, inIface); 
			}
			
			break;
			
		case ARP.OP_REPLY:
			
			System.out.println("Received a ARP reply.");
			
			// Check if reply is for one of my interfaces
			if (targetIp != inIface.getIpAddress()){ 
				break; 
			}
			
			// Update ARP cache with contents of ARP reply

			ArpRequest request = this.arpCache.insert(
					new MACAddress(arpPacket.getSenderHardwareAddress()),
					sourceIp);

			// Process pending ARP request entry, if there is one
			if (request != null)
			{
				
				IPv4 waitingIpPacket = null;
				ARP waitingArpPacket = null;
				int waitingTargettIp = 0;
				
				for (Ethernet packet : request.getWaitingPackets()) {
					/*********************************************************/
					/* TODO: send packet waiting on this request             */
					
					/*********************************************************/
					
					if(packet.getEtherType() == Ethernet.TYPE_ARP){
					
						waitingIpPacket = (IPv4)packet.getPayload();
						
						waitingArpPacket = (ARP)waitingIpPacket.getPayload();
						
						waitingTargettIp = ByteBuffer.wrap(
								waitingArpPacket.getTargetProtocolAddress()).getInt();
						
						/* In this moment, the Router received the reply after sending a ARP request via broadcast.
						 * Then, the ArpCache was filled with the pair MAC-IP and that request has to be removed from the waiting list.
						 */
						
						if(sourceIp == waitingTargettIp){ // Check if that ARP request left from my interface.
							request.getWaitingPackets().remove(packet); // Remove the packet from the waiting list.
						}
					
					}
					
					
				}
			}
			break;
		}
	}
	

	
private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
	
		
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int destinationIP = ipPacket.getDestinationAddress();
		
		if (destinationIP == RIP.RIP_MULTICAST_IP && etherPacket.getSourceMACAddress() != inIface.getMacAddress().toBytes()) {
			
			System.out.println("Entered point 1");
			
			multiCastResponse(etherPacket, inIface);
			return;
		}
		
		System.out.println("Entered point 2");
		// Case 1: destined for interface
		
		boolean sentToInterface = false;
		
		for(Iface ifaceRouter : interfaces.values()){
			
			if (ifaceRouter.getIpAddress() == destinationIP){ // If the packer was sent to an router's interfaces.
				System.out.println("Packet addressed to one of my interfaces.");
				reRouteInterface(etherPacket, inIface);
				sentToInterface = true;
				return;
			}
		}
		
		// Case 2: destined to another IP.
		
		if(!sentToInterface){
			System.out.println("Packet addressed to other IP.");
			reRouteNonInterface(etherPacket, inIface);
	    	return;
		}
		
		return;
	}
	
private void reRouteNonInterface(Ethernet etherPacket, Iface inIface) {
	
	
	IPv4 ipPacket = null;
	
	if(etherPacket.getEtherType() == Ethernet.TYPE_IPv4) { // An Ethernet frame has the Type field.
		ipPacket = (IPv4)etherPacket.getPayload();
	}
	
	if (!verifyCheckSumIP(ipPacket)) {
		 // corrupt packet. Error
		sendICMPMessage(ipPacket.getDestinationAddress(), ipPacket.getSourceAddress(), (byte) 0, (byte) 0, null);
		// TODO
		return;
	 }
	 
	// decrement TTL
	byte ttl = ipPacket.getTtl();
	
	if(ttl > 0) {
		ttl -= 1;
		ipPacket.setTtl(ttl);
		
	} else {
		
		// If the TTL is 0, so the packet should be dropped.
		
		return;
		
	}
	
	ipPacket.setChecksum((byte) 0);
	ipPacket.serialize();
	
	 
	// Find IP longest prefix match
	int destinationIP = ipPacket.getDestinationAddress();		
	
	// find the IP address in the routing table with the longest prefix match by subtraction comparison
	RouteTableEntry nextHop = null;
	int lowerNumber = destinationIP;
	
	int subnet = 0;
			
	for (RouteTableEntry entry : routeTable.getEntries()) {
		
		subnet = entry.getDestinationAddress() & entry.getMaskAddress();
		
		if((destinationIP & entry.getMaskAddress()) == subnet){
			int  tempDiff = Math.abs((destinationIP & entry.getMaskAddress()) - entry.getDestinationAddress());
			if(tempDiff < lowerNumber) {
				nextHop = entry;
				lowerNumber = tempDiff;				
			}
		}	
	}
	
	// retrieve the next-hop MAC address corresponding to the IP
	ArpEntry entry = arpCache.lookup(nextHop.getDestinationAddress());
	
	if (entry == null) {
		
		this.arpCache.waitForArp(etherPacket, this.interfaces.get(nextHop.getInterface()), nextHop.getDestinationAddress());
		
		// TODO What to do while the router is trying to discover the MAC?
		
		return;
		
	} else {
		Iface ifaceOut =  this.interfaces.get(nextHop.getInterface());
				
		if(ifaceOut == null) {
			// TODO
			sendICMPMessage(ipPacket.getDestinationAddress(), ipPacket.getSourceAddress(), (byte) 0, (byte) 0, null);
		}
		
		etherPacket.setPayload(ipPacket);
		etherPacket.setDestinationMACAddress(entry.getMac().toBytes());
		etherPacket.setSourceMACAddress(ifaceOut.getMacAddress().toBytes());
		
		sendPacket(etherPacket, ifaceOut);
	}
	
}

	private void multiCastResponse(Ethernet etherPacket, Iface inIface) {
		
		for(RouteTableEntry rtEntry : this.routeTable.getEntries()){
			
			// It is local interface.
			
			if (rtEntry.getGatewayAddress() == 0) {
				
				Iface iface = this.interfaces.get(rtEntry.getInterface());
				
				etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
				etherPacket.setDestinationMACAddress(RIP.BROADCAST_MAC);
				
				sendPacket(etherPacket, iface);
				
				System.out.println("Packet sent to broadcast.");
				
			} else { // Send to the next hop.
				
				IPv4 ipPacket = (IPv4)etherPacket.getPayload();
				
			}
			
			
		}
		
	}
	
	private void reRouteInterface(Ethernet etherPacket, Iface inIface) {
		
		IPv4 ipPacket = null;
		ICMP icmpPacket = null;
		
		if(etherPacket.getEtherType() == Ethernet.TYPE_IPv4) { // An Ethernet frame has the Type field.
			ipPacket = (IPv4)etherPacket.getPayload();
			if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){ // An IPv4 packet has the Protocol field.
				icmpPacket = (ICMP)ipPacket.getPayload();
			}
		}
		
		// Verify if the packet is a ICMP echo request.
		
		if(icmpPacket != null) { 
			if (verifyCheckSumICMP(icmpPacket)) {
	
				if (icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {	
					
					System.out.println("Received a echo request.");
					// Send a echo reply to the source address.
					sendICMPMessage(ipPacket.getDestinationAddress(), ipPacket.getSourceAddress(), (byte) 0, (byte) 0, icmpPacket); 
					return;
					
				} else {
					System.out.println("It is ICMP, but not echo request.");
				}
			} else {
				System.out.println("It is ICMP, but its checksum is invalid.");
			}
		}

		// Check if UDP or TCP packet
		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
			
			UDP udpPacket = (UDP)ipPacket.getPayload();
			
			// If it is UDP and port 520, repass the request to RIP.
			if(udpPacket.getDestinationPort() == 520) {
				System.out.println("Received a 520 UDP");
				rip.handlePacket(etherPacket, inIface);
			} else {
				sendICMPMessage(ipPacket.getDestinationAddress(), ipPacket.getSourceAddress(), (byte) 3, (byte) 3, icmpPacket); // Port unreachable
			}

		} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
			System.out.println("Received a TCP.");
			sendICMPMessage(ipPacket.getDestinationAddress(), ipPacket.getSourceAddress(), (byte) 3, (byte) 3, icmpPacket); // Port unreachable
			
		} else {
			// Ignore the packet.
			System.out.println("Packet ignored.");
			return;
		} 
		

	}
	
	/**
	 * Determines whether a packet's checksum is valid
	 * @param etherPacket
	 * @return boolean whether checksum is valid
	 */
	private boolean verifyCheckSumIP(IPv4 ipPacket) { // Only IP Packets contains checksum.
		
		int previousCheckSum = ipPacket.getChecksum();
		
		// Recalculating the checksum.
		
		ipPacket.setChecksum((short) 0);
		ipPacket.serialize();
		
		if(previousCheckSum == ipPacket.getChecksum()) { // The packet is correct.
			return true;
		} else {
			return false;
		}

	}
	
	
	
	/**
	 * Determines whether a packet's checksum is valid
	 * @param etherPacket
	 * @return boolean whether checksum is valid
	 */
	private boolean verifyCheckSumICMP(ICMP icmpPacket) { // Only IP Packets contains checksum.
		
		int previousCheckSum = icmpPacket.getChecksum();
		
		// Recalculating the checksum.
		
		icmpPacket.setChecksum((short) 0);
		icmpPacket.serialize();
		
		if(previousCheckSum == icmpPacket.getChecksum()) { // The packet is correct.
			return true;
		} else {
			return false;
		}
	}
	
	
	
	
	/**
	 * Send an ICMP reply packet for a received ARP request packet.
	 * @param etherPacket request packet received by the router
	 * @param iface interface on which the request packet was received
	 * @param originIcmp is optional.
	 */
	void sendICMPMessage(int srcIp, int destIp, byte code, byte type, ICMP originIcmp){
		
		int netMask = Util.dottedDecimalToInt("255.255.255.255");
		
		ArpEntry arpEntry = this.arpCache.lookup(destIp);
		
		if(arpEntry == null) {
			System.out.println("Unknown IP (it is not in the ArpCache).");
			return;
		}
		
		RouteTableEntry rtEntry = this.routeTable.findEntry(destIp, netMask); // Get the route entry for this IP.
		Iface iface = this.interfaces.get(rtEntry.getInterface()); // Get the interface to reach this IP.
		
		MACAddress macDest = arpEntry.getMac(); 		
		MACAddress macSrc = iface.getMacAddress();
		
		//int addrSrc = iface.getIpAddress();
		
		// Populate ICMP header

		ICMP icmpPacket = new ICMP();
		
		icmpPacket.setIcmpCode(code);
		icmpPacket.setIcmpType(type);
		icmpPacket.setChecksum((short) 0);
		
		if(originIcmp != null){
			icmpPacket.setPayload(originIcmp.getPayload());
		}
		
		icmpPacket.serialize();

		
		// Populate IPv4 header
		
		IPv4 ipPacket = new IPv4();
		ipPacket.setDestinationAddress(destIp);
		ipPacket.setSourceAddress(srcIp);
		ipPacket.setProtocol(IPv4.PROTOCOL_ICMP);
		ipPacket.setTtl((byte) 64);
		ipPacket.setVersion((byte) 4);
		ipPacket.setFragmentOffset((byte) 0);
		ipPacket.setFlags((byte) 2);
		ipPacket.setChecksum((byte) 0);
		
		ipPacket.setPayload(icmpPacket);
		
		// Generation checksum

		ipPacket.serialize();

		// Populate Ethernet header
		Ethernet etherPacket = new Ethernet();
		
		etherPacket.setDestinationMACAddress(macDest.toBytes());
		etherPacket.setSourceMACAddress(macSrc.toBytes());
		etherPacket.setEtherType(Ethernet.TYPE_IPv4);
		
		etherPacket.setPayload(ipPacket);
		
		// Send ICMP request
		System.out.println("Sending ICMP message");
		
		this.sendPacket(etherPacket, iface);
		
	}
	
	
}
