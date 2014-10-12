package edu.wisc.cs.sdn.sr;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import edu.wisc.cs.sdn.sr.vns.VNSComm;

import net.floodlightcontroller.packet.ARP;
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
	{ return this.vnsComm.sendPacket(etherPacket, iface.getName()); }
	
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
		
		

		if (etherPacket.getEtherType() == Ethernet.TYPE_ARP) {	
			// Case 1: packet is of type ARP
			handleArpPacket(etherPacket, inIface);	
			
		} else if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
			// Case 2: packet is of type IP 
			handleIpPacket(etherPacket, inIface);
					
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
		int targetIp = ByteBuffer.wrap(
				arpPacket.getTargetProtocolAddress()).getInt();
		
		switch(arpPacket.getOpCode())
		{
		case ARP.OP_REQUEST:
			// Check if request is for one of my interfaces
			if (targetIp == inIface.getIpAddress())
			{ this.arpCache.sendArpReply(etherPacket, inIface); }
			break;
		case ARP.OP_REPLY:
			// Check if reply is for one of my interfaces
			if (targetIp != inIface.getIpAddress())
			{ break; }
			
			// Update ARP cache with contents of ARP reply
			ArpRequest request = this.arpCache.insert(
					new MACAddress(arpPacket.getTargetHardwareAddress()),
					targetIp);
			
			// Process pending ARP request entry, if there is one
			if (request != null)
			{
				
				ARP waitingArpPacket = null;
				int waitingTargettIp = 0;
				
				for (Ethernet packet : request.getWaitingPackets())
				{
					/*********************************************************/
					/* TODO: send packet waiting on this request             */
					
					/*********************************************************/
					
					
					
					
					waitingArpPacket = (ARP)packet.getPayload();
					waitingTargettIp = ByteBuffer.wrap(
							waitingArpPacket.getTargetProtocolAddress()).getInt();
					
					// In this moment, the Router received the reply after sending a ARP request via broadcast.
					// Then, the ArpCache was filled with the pair MAC-IP and that request has to be removed from the waiting list.
					
					if(targetIp == waitingTargettIp){ // Check if that ARP request left from my interface.
						request.getWaitingPackets().remove(packet); // Remove the packet from the waiting list.
					}
					
					
					
					
					
				}
			}
			break;
		}
	}
	
	
	
	
	
private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int destinationIP = ipPacket.getDestinationAddress();
		
		// Case 1: destined for interface
		
		//if (arpCache.getRequests().containsValue(etherPacket.getDestinationMAC())) {
		
		boolean sentToInterface = false;
		
		for(Iface ifaceRouter : interfaces.values()){
			if (ifaceRouter.getIpAddress() == destinationIP){ // If the packer was sent to an interface of router
				
				reRouteInterface(etherPacket, inIface);
				sentToInterface = true;
				return;
			}
		}
		
		if(!sentToInterface){
			reRouteNonInterface(etherPacket, inIface);
	    	return;
		}
		
		return;
	}
	
	private void reRouteNonInterface(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		 if (verifyCheckSumIP(ipPacket)) {
			 // TODO: send error message
			 return;
		 }
		 
		 // decrement TTL
		IPv4 pkt = (IPv4) etherPacket.getPayload();
		
		byte ttl = pkt.getTtl();
		ttl -= 1;
		pkt.setTtl(ttl);
		
		/* TODO
		 * Find out which entry in the routing table has the longest prefix match with the destination IP address.
		 * Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it's there, 
		 * send the packet. Otherwise, call waitForArp(...) function in the ARPCache class to send an ARP 
		 * request for the next-hop IP, and add the packet to the queue of packets waiting on this ARP request.
		 */
		
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
		
		if(icmpPacket != null) { 
			if (verifyCheckSumICMP(icmpPacket)) {
				if (icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {	
					sendICMPMessage(ipPacket.getDestinationAddress(), inIface.getSubnetMask(), (byte) 0, (byte) 0); // Send a echo reply.

				}
			}
		}

		// Check if UDP or TCP packet
		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
			
			UDP udpPacket = (UDP)ipPacket.getPayload();
			
			if(udpPacket.getDestinationPort() == 520) {
				rip.handlePacket(etherPacket, inIface);
			} else {
				sendICMPMessage(ipPacket.getDestinationAddress(), inIface.getSubnetMask(), (byte) 3, (byte) 3); // Port unreachable
			}

		} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
			sendICMPMessage(ipPacket.getDestinationAddress(), inIface.getSubnetMask(), (byte) 3, (byte) 3); // Port unreachable
			
		} else {
			// Ignore the packet.
			return;
		}
		

	}
	
	/**
	 * Determines whether a packet's checksum is valid
	 * @param etherPacket
	 * @return boolean whether checksum is valid
	 */
	private boolean verifyCheckSumIP(IPv4 ipPacket) { // Only IP Packets contains checksum.
		
		// TODO
		
		return true;
	}
	
	
	
	/**
	 * Determines whether a packet's checksum is valid
	 * @param etherPacket
	 * @return boolean whether checksum is valid
	 */
	private boolean verifyCheckSumICMP(ICMP icmpPacket) { // Only IP Packets contains checksum.
		
		// Create a packet copy and recalculate this packet's checksum
		ICMP icmpPacketCopy = new ICMP();
		icmpPacketCopy =  (ICMP) icmpPacket.clone();
		icmpPacketCopy.setChecksum((short) 0);
		icmpPacketCopy.serialize();

		if (icmpPacketCopy.getChecksum() == icmpPacket.getChecksum()) {
			return true;
		} else {
			return false;
		}
	}
	
	
	
	
	/**
	 * Send an ICMP reply packet for a received ARP request packet.
	 * @param etherPacket request packet received by the router
	 * @param iface interface on which the request packet was received
	 */
	void sendICMPMessage(int destIp, int netMask, byte code, byte type){
		
		RouteTableEntry rtEntry = this.routeTable.findEntry(destIp, netMask); // Get the route entry for this IP.
		Iface iface = this.interfaces.get(rtEntry.getInterface()); // Get the interface to reach this IP.
		
		MACAddress macDest = this.arpCache.lookup(destIp).getMac(); 
		MACAddress macSrc = iface.getMacAddress();
		int addrSrc = iface.getIpAddress();
		
		// Populate ICMP header

		ICMP icmpPacket = new ICMP();
		
		icmpPacket.setIcmpCode(code);
		icmpPacket.setIcmpType(type);
		icmpPacket.resetChecksum();
		
		// Populate IPv4 header
		
		IPv4 ipPacket = new IPv4();
		ipPacket.setDestinationAddress(destIp);
		ipPacket.setSourceAddress(addrSrc);
		ipPacket.setProtocol(IPv4.PROTOCOL_ICMP);
		// **** Maybe more headers here... *************************** //
		
		ipPacket.resetChecksum();
		
		// Inserting the ICMP into the IPv4
		
		ipPacket.setPayload(icmpPacket);
	
	
		// Populate Ethernet header
		Ethernet etherPacket = new Ethernet();
		etherPacket.setDestinationMACAddress(macDest.toBytes());
		etherPacket.setSourceMACAddress(macSrc.toBytes());
		etherPacket.setEtherType(Ethernet.TYPE_IPv4);
		
		
		etherPacket.setPayload(ipPacket);
		
		// Send ICMP request
		System.out.println("Send ICMP reply");
		System.out.println(icmpPacket.toString());
		this.sendPacket(etherPacket, iface);
	}
	
	
}
