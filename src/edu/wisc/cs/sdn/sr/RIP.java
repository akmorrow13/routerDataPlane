package edu.wisc.cs.sdn.sr;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
  * Implements RIP. 
  * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson
  */
public class RIP implements Runnable
{
	
	public static final int INFINITE_COST = 17;
	
	
    public static final int RIP_MULTICAST_IP = 0xE0000009;
    public static final byte[] BROADCAST_MAC = {(byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
    
    /** Send RIP updates every 10 seconds */
    private static final int UPDATE_INTERVAL = 10;

    /** Timeout routes that neighbors last advertised more than 30 seconds ago*/
    private static final int TIMEOUT = 30;

    /** Router whose route table is being managed */
	private Router router;

    /** Thread for periodic tasks */
    private Thread tasksThread;  

	public RIP(Router router)
	{ 
        this.router = router; 
        this.tasksThread = new Thread(this);
    }

	public void init()
	{
        // If we are using static routing, then don't do anything
        if (this.router.getRouteTable().getEntries().size() > 0)
        { return; }

        System.out.println("RIP: Build initial routing table");
        for(Iface iface : this.router.getInterfaces().values())
        {
        	
            this.router.getRouteTable().addEntry(
                    (iface.getIpAddress() & iface.getSubnetMask()),
                    0, // No gateway for subnets this router is connected to
                    iface.getSubnetMask(), iface.getName());
            
            
            RouteTableEntry rtEntry = this.router.getRouteTable().findEntry((iface.getIpAddress() & iface.getSubnetMask()), iface.getSubnetMask());
            rtEntry.setCost(0);
            
        }
        System.out.println("Route Table:\n"+this.router.getRouteTable());

		this.tasksThread.start();

		// Send RIP request in broadcast.
		sendRIPMessageMulticast(RIPv2.COMMAND_REQUEST);
		
	}

    /**
      * Handle a RIP packet received by the router.
      * @param etherPacket the Ethernet packet that was received
      * @param inIface the interface on which the packet was received
      */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
        // Make sure it is in fact a RIP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        { return; } 
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
        { return; } 
		UDP udpPacket = (UDP)ipPacket.getPayload();
        if (udpPacket.getDestinationPort() != UDP.RIP_PORT)
        { return; }
		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();
		

		if(ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {// A new router is asking for my table.
			
			System.out.println("Received a RIPv2 request.");
			
			sendRIPResponseOneHost(etherPacket, inIface, RIPv2.COMMAND_RESPONSE);
			
		} else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) { // The server should update your list and forward it to the other routers.
			
			System.out.println("Received a RIPv2 response.");
			
			updateRouteTable(etherPacket, inIface);
			
		}
		
		
		
	}
    
    /**
      * Perform periodic RIP tasks.
      */
	@Override
	public void run() 
    {
		while(true) {

			try { 
				TimeUnit.SECONDS.sleep(RIP.UPDATE_INTERVAL);

				// Sends updates and checks for timeout every 10 seconds.

				checkForTimeout();
				sendRIPMessageMulticast(RIPv2.COMMAND_RESPONSE);
				
				
			}catch (InterruptedException e) {
				return;
			}
		}
		
    }
	
	
	/**
     * Checks if any entry in the route table timed out and remove it.
     */
	private void checkForTimeout() {
		
		boolean shouldSendAdvice = false;
		
		System.out.println("Checking for timeout.");
		
		Iterator<RouteTableEntry> iterator = this.router.getRouteTable().getEntries().iterator();
		RouteTableEntry rtEntry = null;
		
		while (iterator.hasNext()) {
			
			// if an entry is a direct neighbor, do nothing
			rtEntry = iterator.next();
			
			if (rtEntry.getCost() < 1) {
				
				continue;
				
			} else {
				
				long currentTime = System.currentTimeMillis();
				
				if (currentTime - rtEntry.getTimStamp()  > (TIMEOUT * 1000)) {
					// The line below generates a ConcurrentModificationException
					
					//this.router.getRouteTable().removeEntry(rtEntry.getDestinationAddress(), rtEntry.getMaskAddress());
					System.out.println("Entry " + Util.intToDottedDecimal(rtEntry.getGatewayAddress()) + " timed out.");
					
					rtEntry.setCost(17); // Set to infinte.
					
					//iterator.remove();
					
					shouldSendAdvice = true;
					
				}
			}
		}
		
		// If some host timed out, the router should advice the others about that.
		
		if(shouldSendAdvice) {
			sendRIPMessageMulticast(RIPv2.COMMAND_RESPONSE);
		}
		
	}
	
	/**
     * Updates the route table based in one response which was received.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */
	public void updateRouteTable(Ethernet etherPacket, Iface inIface) {
		
		System.out.println("Updated route table.");
		System.out.println(this.router.getRouteTable().toString());
		
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		UDP udpPacket = (UDP)ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();
		
		for (RIPv2Entry ripEntry : ripPacket.getEntries()) {
					
				RouteTableEntry rtEntry = this.router.getRouteTable().findEntry(ripEntry.getAddress(), ripEntry.getSubnetMask());
				RouteTableEntry newRtEntry = null;
				
				newRtEntry  = new RouteTableEntry(ripEntry.getAddress(), ipPacket.getSourceAddress(), 
						ripEntry.getSubnetMask(), inIface.getName());
				
				newRtEntry.setCost(ripEntry.getMetric() + 1);
				newRtEntry.setTimeStamp(System.currentTimeMillis());
				
				if(newRtEntry.getCost() >= INFINITE_COST) { // Infinite
					// Drop this packet.
					return;
				}
				
				if (rtEntry == null) {
					
					this.router.getRouteTable().addEntry(newRtEntry);
					
				} else {
					
					if (rtEntry.getCost() >= (ripEntry.getMetric() + 1)) {
						
						this.router.getRouteTable().removeEntry(rtEntry.getDestinationAddress(), rtEntry.getMaskAddress());
						this.router.getRouteTable().addEntry(newRtEntry);
						
					} else {
						
						// If this RIP is not better than the current, drop it.
						
					}
					
				}
								
				
			}
		
	}

	
	/**
     * Sends a RIP message to multicast.
     */
	
	public void sendRIPMessageMulticast(byte ripType) {
		
		RIPv2 ripPacket = null;
		
		if(ripType == RIPv2.COMMAND_REQUEST) {
			ripPacket = makeRipPacket(RIPv2.COMMAND_REQUEST);
			
		} else if (ripType == RIPv2.COMMAND_RESPONSE) {
			ripPacket = makeRipPacket(RIPv2.COMMAND_RESPONSE);
			
		} else {
			return;
		}
	
		
		UDP udpPacket = new UDP();
		IPv4 ipPacket = new IPv4();;
		Ethernet etherPacket = new Ethernet();
		
		udpPacket.setDestinationPort(UDP.RIP_PORT);
		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setPayload(ripPacket);
		udpPacket.serialize();
		
		ipPacket.setDestinationAddress(RIP_MULTICAST_IP);
		ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
		ipPacket.setTtl((byte) 64);
		ipPacket.setVersion((byte) 4);
		ipPacket.setFragmentOffset((byte) 0);
		ipPacket.setFlags((byte) 2);
		ipPacket.setChecksum((byte) 0);
		ipPacket.setPayload(udpPacket);
		
		etherPacket.setDestinationMACAddress(BROADCAST_MAC);
		etherPacket.setEtherType(Ethernet.TYPE_IPv4);
		etherPacket.setPayload(ipPacket);
		
		// TODO The split horizon is implemented below, but I couldn't test it yet.
		
		RIPv2 ripPacketCopy = (RIPv2) ripPacket.clone();
		
		for(Iface iface : this.router.getInterfaces().values()) {
			
			ripPacket = (RIPv2) ripPacketCopy.clone();
			
			for(RouteTableEntry rtEntry : this.router.getRouteTable().getEntries()) {
				
				if(rtEntry.getInterface().equals(iface.getName()) && rtEntry.getGatewayAddress() != 0) { // Non local entry found.
					
					for(RIPv2Entry ripEntry : ripPacket.getEntries()) {
						if(ripEntry.getNextHopAddress() == rtEntry.getGatewayAddress()) {
							
							// Remove from my RIP packet that the destination can reach a network using me, 
							// because, actually, I learned this route from it.
							
							ripPacket.getEntries().remove(ripEntry); 
						}
					}
					
					
				}
			}
	

			ipPacket.setSourceAddress(iface.getIpAddress());
			
			etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
			etherPacket.setDestinationMACAddress(RIP.BROADCAST_MAC);
			
			this.router.sendPacket(etherPacket, iface);
				
				
			} 
		
	}
	
	
	
	
	
	/**
     * Sends a RIP response to one specific host.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */
	public void sendRIPResponseOneHost(Ethernet etherPacket, Iface inIface, byte ripType){
		
		System.out.println("Sending RIP in unicast.");
		
		// Make sure it is in fact a RIP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        { return; } 
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
        { return; } 
		UDP udpPacket = (UDP)ipPacket.getPayload();
        if (udpPacket.getDestinationPort() != UDP.RIP_PORT)
        { return; }		
		
        RIPv2 ripPacket = makeRipPacket(RIPv2.COMMAND_RESPONSE);
		
		// RIPv2 works in Application layer, under UDP
		
		udpPacket.setPayload(ripPacket);
		udpPacket.setChecksum((short) 0);
		udpPacket.serialize();
		
		
		// UDP over IP
		
		ipPacket.setDestinationAddress(ipPacket.getSourceAddress());
		ipPacket.setSourceAddress(inIface.getIpAddress());
		ipPacket.setTtl((byte) 64);
		ipPacket.setChecksum((short) 0);
		
		ipPacket.setPayload(udpPacket);
		
		ipPacket.serialize();
		
		// IP over Ethernet
		
		etherPacket.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		etherPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
		
		etherPacket.setPayload(ipPacket);
		
		// Split to horizon
 
		
		for(RIPv2Entry ripEntry : ripPacket.getEntries()){
			
			if(ripEntry.getNextHopAddress() == ipPacket.getDestinationAddress()) {
				
				ripPacket.getEntries().remove(ripEntry);
				
			}
			
		}
		
		
		this.router.handlePacket(etherPacket, inIface);
		
		
	}
	
	
	/**
     * Generates a RIP packet based in the route table.
     * @return ripPacket RIP packet with information of the route table.
     */
	public RIPv2 makeRipPacket(byte ripType) {
		
		RIPv2 ripPacket = new RIPv2();
			
		List<RIPv2Entry> myEntries = new LinkedList<RIPv2Entry>();
		
		RIPv2Entry ripEntry;
		
		for(RouteTableEntry rtEntry : this.router.getRouteTable().getEntries()) {
			
			ripEntry = new RIPv2Entry();
			
			ripEntry.setAddress(rtEntry.getDestinationAddress());
			ripEntry.setSubnetMask(rtEntry.getMaskAddress());
			
			// Metric == cost
			
			ripEntry.setMetric(rtEntry.getCost());
			
			ripEntry.setRouteTag(this.router.getTopo());
			
			// lookup the next hop address
			Iface nextIface = this.router.getInterface(rtEntry.getInterface());
			ripEntry.setNextHopAddress(nextIface.getIpAddress());
			
			myEntries.add(ripEntry);
					
		}
		
		ripPacket.setEntries(myEntries);
		ripPacket.setCommand(ripType);
	
		return ripPacket;
		
	}

	
}
