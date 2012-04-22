
public class UDPPacket extends IPPacket{

	//UDP packet locations
	final int UDP_PACKET_START = IP_PAYLOAD_START;
	
	final int UDP_PORT_LEN = (int)(16/BITS_IN_BYTE);
	final int UDP_SRC_PORT = UDP_PACKET_START;
	final int UDP_DST_PORT = UDP_SRC_PORT + UDP_PORT_LEN;
	
	//variables
	public int source_port;
	public int destination_port;

	public UDPPacket(byte[] packet) {
		super(packet);
		this.packet_type = "udp";
		parse();
	}//end constructor
	
	public String toString() {
		String out = super.toString();
		
		out+=outln("Source Port: "+source_port);
		out+=outln("Destination Port: "+destination_port);
		
		return out;
	}//end toString
	
	public boolean is_type(String type){
		return ( type.equals("all") || type.equals("eth") || type.equals("ip") || type.equals("udp") );
	}//end is_type
	
	private void parse(){
		byte[] srcP = new byte[4];
		byte[] dstP = new byte[4];
		
        System.arraycopy(packet, UDP_SRC_PORT, srcP, 2, UDP_PORT_LEN);
        System.arraycopy(packet, UDP_DST_PORT, dstP, 2, UDP_PORT_LEN);
        
        source_port = bytesToInt(srcP);
        destination_port = bytesToInt(dstP);
	}//end parse
	
	public UDPPacket port_filter(Integer source_port_start,
			Integer source_port_end, Integer destination_port_start,
			Integer destination_port_end) {
		if(source_port_start!=null && source_port_end!=null){
			if(source_port_start <= source_port && source_port <= source_port_end) return this;
		}
		if(destination_port_start!=null && destination_port_end!=null){
			if(source_port_start <= destination_port && destination_port <= source_port_end) return this;
		}
		return null;
	}//end port_filter

}//end UDPPacket