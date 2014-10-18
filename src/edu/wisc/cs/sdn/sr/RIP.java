package edu.wisc.cs.sdn.sr;

import java.util.LinkedList;
import java.util.List;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.MACAddress;

/**
  * Implements RIP. 
  * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson
  */
public class RIP implements Runnable
{
    private static final int RIP_MULTICAST_IP = 0xE0000009;
    private static final byte[] BROADCAST_MAC = {(byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
    
    /** Send RIP updates every 10 seconds */
    private static final int UPDATE_INTERVAL = 10;

    /** Timeout routes that neighbors last advertised more than 30 seconds ago*/
    private static final int TIMEOUT = 30;

    /** Router whose route table is being managed */
	private Router router;

    /** Thread for periodic tasks */
    private Thread tasksThread;
    
    
    /** Helps in the relation between update and timeout  */
    
    private int countUpdates = 0;
    

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

        /*********************************************************************/
        /* TODO: Add other initialization code as necessary                  */

        /*********************************************************************/
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

        /*********************************************************************/
        /* TODO: Handle RIP packet                                           */

        /*********************************************************************/
		
		
		if(ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {// A new router is asking for my table.
			
			sendRIPResponseOneHost(etherPacket, inIface);
			
		} else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) { // The server should update your list and forward it to the other routers.
			
			updateRouteTable(etherPacket, inIface);
			
		}
		
		
		
	}
    
    /**
      * Perform periodic RIP tasks.
      */
	@Override
	public void run() 
    {
        /*********************************************************************/
        /* TODO: Send period updates and time out route table entries        */

        /*********************************************************************/
		
		// Update 
		
		
		
		try { 
			if(countUpdates < 3){
				Thread.sleep(this.UPDATE_INTERVAL); 
			} else {
				Thread.sleep(3 * this.UPDATE_INTERVAL);
				this.countUpdates = 0;
				checkForTimeout();
			}
			
			// Send RIPResponse in broadcast.
			
			sendRIPResponseBroadcast();
			
		}catch (InterruptedException e) {
			return;
		}

		
    }
	
	
	/**
     * Checks if any entry in the route table timed out and remove it.
     */
	public void checkForTimeout() {
		
		// TODO
		
		// Basically, we check if one route which has cost 1 (that is, the router's neighbors)
		// does not send a RIP packet in the last 30 seconds.
		
		// If not, the route removes its information from the route tabble and sends new response in brodcast to 
		// inform all the other routers about that.
		
		// For that, I think the RouteTableEntry has to save more information, like from who the router learned that line
		// and the time which it received the last update.
		
	}
	
	/**
     * Updates the route table based in one response which was received.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */
	public void updateRouteTable(Ethernet etherPacket, Iface inIface) {
		
		// TODO
		
	}
	
	/**
     * Sends a RIP response to broadcast.
     */
	public void sendRIPResponseBroadcast() {
		
		RIPv2 ripPacket = makeRipPacket();
		UDP udpPacket = new UDP();
		IPv4 ipPacket = new IPv4();;
		Ethernet etherPacket = new Ethernet();
		
		
		udpPacket.setDestinationPort((short) 520);
		udpPacket.setSourcePort((short) 520);
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
		
		for(Iface iface : router.getInterfaces().values()) {
		
			ipPacket.setSourceAddress(iface.getIpAddress());
			ipPacket.serialize();
			
			etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
			
			sendRIPResponseOneHost(etherPacket, iface);
			
		}
		
	}
	
	
	/**
     * Sends a RIP response to one specific host.
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */
	public void sendRIPResponseOneHost(Ethernet etherPacket, Iface inIface){
		
		// Make sure it is in fact a RIP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        { return; } 
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
        { return; } 
		UDP udpPacket = (UDP)ipPacket.getPayload();
        if (udpPacket.getDestinationPort() != UDP.RIP_PORT)
        { return; }		
		
        RIPv2 ripPacket = makeRipPacket();
		
		// RIPv2 works in Application layer, under UDP
		
		udpPacket.setPayload(ripPacket);
		udpPacket.setChecksum((short) 0);
		udpPacket.serialize();
		
		
		// UDP over IP
		
		int tempIp = ipPacket.getDestinationAddress();
		ipPacket.setDestinationAddress(ipPacket.getSourceAddress());
		ipPacket.setSourceAddress(tempIp);
		ipPacket.setTtl((byte) 64);
		ipPacket.setChecksum((short) 0);
		
		ipPacket.setPayload(udpPacket);
		
		ipPacket.serialize();
		
		// IP over Ethernet
		
		MACAddress tempMac = etherPacket.getDestinationMAC();
		etherPacket.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		etherPacket.setSourceMACAddress(tempMac.toBytes());
		
		etherPacket.setPayload(ipPacket);
		
		// Send the packet.
		this.router.handlePacket(etherPacket, inIface);
		
		
	}
	
	
	/**
     * Generates a RIP packet based in the route table.
     * @return ripPacket RIP packet with information of the route table.
     */
	public RIPv2 makeRipPacket() {
		
		RIPv2 ripPacket = new RIPv2();
			
		List<RIPv2Entry> myEntries = new LinkedList<RIPv2Entry>();
		
		RIPv2Entry ripEntry;
		
		for(RouteTableEntry rtEntry : this.router.getRouteTable().getEntries()) {
			
			ripEntry = new RIPv2Entry();
			
			ripEntry.setAddress(rtEntry.getDestinationAddress());
			ripEntry.setSubnetMask(rtEntry.getMaskAddress());
			
			// Metric == cost
			
			ripEntry.setMetric(rtEntry.getCost());
			
			// One way to identify the router (in the future, to avoid the count to infinite).
			// Sincerely, I don't know how to idenfity it (maybe a new attribute).
			
			ripEntry.setRouteTag((short)(this.router.hashCode()));
			
			myEntries.add(ripEntry);
			
			
		}
		
		ripPacket.setEntries(myEntries);
		ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);
	
		return ripPacket;
		
	}

	
}
