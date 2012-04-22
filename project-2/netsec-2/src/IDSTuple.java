import java.util.Vector;


public class IDSTuple {
	
	//SID values
	final static int ARP_SID = 1;
	final static int CORRECT_SID = 1;
	final static int OVERLAP_SID = 2;
	final static int OVERSIZE_SID = 3;
	final static int TIMEOUT_SID = 4;

	int SID;
	EthernetPacket PACKET;
	String TYPE;
	Vector<EthernetPacket> FRAGMENTS = new Vector<EthernetPacket>();
	
	
	public IDSTuple(int sid, EthernetPacket packet, Vector<EthernetPacket> fragments) {
		this.SID = sid;
		this.PACKET = packet;
		this.FRAGMENTS = fragments;
		this.TYPE = FRAGMENTS.elementAt(0).packet_type;
	}//end constructor
	
	//ARP constructor
	public IDSTuple(int sid, EthernetPacket packet) {
		this.SID = sid;
		this.PACKET = packet;
		FRAGMENTS.add(this.PACKET);
	}//end constructor
	
	public String toString(){
		return String.format("[%s](%s) SID: %s [%s fragments]", this.TYPE, calcPacketSize(), this.SID, this.FRAGMENTS.size());
	}//end toString
	
	private String calcPacketSize(){
		int numBytes = PACKET.packet.length;
		int kBytes = numBytes/1024;
		
		return String.valueOf(numBytes)+" b";
		/*
		if(kBytes >= 1){
			return String.valueOf(kBytes)+" kb";
		}else{
			return String.valueOf(numBytes)+" b";
		}//end if/else kilobytes
		*/
		
	}//end packetSize
}
