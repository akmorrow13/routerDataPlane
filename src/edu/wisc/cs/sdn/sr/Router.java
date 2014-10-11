package edu.wisc.cs.sdn.sr;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

import com.sun.org.apache.xerces.internal.impl.xpath.regex.ParseException;

import edu.wisc.cs.sdn.sr.vns.VNSComm;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
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
		
		
		
		if (etherPacket.getEtherType() == etherPacket.TYPE_IPv4) {
			
			// Case 1: packet is of type IP 
			handleIpPacket(etherPacket, inIface);
			
		} else if (etherPacket.getEtherType() == etherPacket.TYPE_ARP) {
			
			// Case 2: packet is of type ARP
			handleArpPacket(etherPacket, inIface);
			
		} else {
			// Case 3: packet is of other type
			// TODO: send back error message
			
		}
		
		
	}
	
	/**
	 * Send an ICMP reply packet for a received ARP request packet.
	 * @param etherPacket request packet received by the router
	 * @param iface interface on which the request packet was received
	 */
	private void sendICMPReply(Ethernet etherPacket, Iface iface, byte code, byte type)
	{
		// Populate Ethernet header
		Ethernet etherReply = new Ethernet();
		etherReply.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		etherReply.setSourceMACAddress(iface.getMacAddress().toBytes());
		etherReply.setEtherType(Ethernet.TYPE_IPv4);
		
		// Populate ICMP header
		ICMP icmpPacket = (ICMP) etherPacket.getPayload();
		ICMP icmpReply = new ICMP();
		
		icmpReply.setIcmpCode(code);
		icmpReply.setIcmpType(type);
		icmpReply.setChecksum((short) 0);
		
		icmpReply.serialize();
		
		// Stack headers
		etherReply.setPayload(icmpReply);
		
		// Send ICMP request
		System.out.println("Send ICMP reply");
		System.out.println(icmpReply.toString());
		this.sendPacket(etherReply, iface);
	}

	/**
	 * Handle an IP packet received on a specific interface.
	 * @param etherPacket the complete ARP packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		
		int destinationIP = -1;
		
		// Case 1: destined for interface
		if (arpCache.getRequests().containsValue(etherPacket.getDestinationMAC())) {
			
			// get IP address from MAC address
		    for (int ip : arpCache.getRequests().keySet()) {

		    	if (arpCache.getRequests().get(ip).getMac().equals(etherPacket.getDestinationMAC())) {
		    		destinationIP = ip;
		    		break;
		    	}
		    }
		    
		    if (destinationIP < 0) {
		    	// TODO: IP address not found. Return error
		    	return;
		    }
		    
		    
		    // check if ip corresponds to an interface on the router
		    RouteTableEntry entry = routeTable.findEntry(destinationIP, inIface.getSubnetMask());
		    
			if (interfaces.containsKey(entry.getInterface())) {
				
				// IP packet destined for one of router's interfaces
				reRouteInterface(etherPacket, inIface);
			
				
			} else {
				
				// IP packet is NOT destined for one of router's interfaces
				 reRouteNonInterface(etherPacket, inIface);
				 
			}
			
		} else {
			
	    	// TODO: IP address not found. Return error
	    	return;
		}
		
		return;
	}
	
	private void reRouteNonInterface(Ethernet etherPacket, Iface inIface) {
		 if (calcCheckSum(etherPacket)) {
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
		
		String packetStr = null;
		
		packetStr = etherPacket.toString();
		
		
		// Check if ICMP packet
		if (packetStr.contains("icmp")) {
			if (calcCheckSum(etherPacket)) {
				
				// echo reply to sending host
				ICMP pkt = (ICMP) etherPacket.getPayload();
				
				if (pkt.getIcmpType() == pkt.TYPE_ECHO_REQUEST) {
					
					sendICMPReply(etherPacket, inIface, pkt.getIcmpCode(), pkt.TYPE_ECHO_REQUEST);
				}
				
				
			}
		}
		// Check if UDP or TCP packet
		if (packetStr.contains("ntp")) {
			
			// parse destination port
			int destPort = -1;
			String packetType = null;
			
			int destStart = packetStr.indexOf("\ntp_dst: ") + 9;
			try {
				destPort = Integer.parseInt(packetStr.substring(destStart));
			} catch (ParseException ex) {
				
				System.out.println("Error parsing destination port for UDP or TCP packet");
				System.exit(-1);
			
			}
			
			// determine packet type: UDP, TCP or other
			IPacket pkt = (IPacket) etherPacket.getPayload();
			if (pkt instanceof UDP) {
				packetType = "UDP";
			} else if (pkt instanceof TCP) {
				packetType = "TCP";
			} else {
				packetType = "other";
			}
			
			if (destPort == 520 && packetType.equals("UDP")) {
				
				// handle RIP packet
				rip.handlePacket(etherPacket, inIface);
				
			} else if (destPort != 520 && (packetType.equals("UDP") || packetType.equals("TCP"))) {
				
				// send an ICMP port unreachable (ICMP type 3, code 3) packet to the sending host
				
				sendICMPReply(etherPacket, inIface, (byte) 3, (byte) 3);

			} else {
				// packet ignored, return nothing
				return;
			}
			
		}
	}
	
	/**
	 * Determines whether a packet's checksum is valid
	 * @param etherPacket
	 * @return boolean whether checksum is valid
	 */
	private boolean calcCheckSum(Ethernet etherPacket) {
		
		ICMP pkt = (ICMP) etherPacket.getPayload();
		
		// Create a packet copy and recalculate this packet's checksum
		ICMP pktCopy = new ICMP();
		pktCopy =  (ICMP) pkt.clone();
		pktCopy.setChecksum((short) 0);
		pktCopy.serialize();

		if (pktCopy.getChecksum() == pkt.getChecksum()) {
			return true;
		}
		
		return false;
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
				for (Ethernet packet : request.getWaitingPackets())
				{
					/*********************************************************/
					/* TODO: send packet waiting on this request             */
					
					/*********************************************************/
				}
			}
			break;
		}
	}
}
