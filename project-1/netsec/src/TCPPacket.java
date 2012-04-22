
public class TCPPacket extends IPPacket{
	
	//tcp packet locations
	final int TCP_PACKET_START = IP_PAYLOAD_START;
	
	final int TCP_PORT_LEN = (int)(16/BITS_IN_BYTE);
	final int TCP_SRC_PORT = TCP_PACKET_START;
	final int TCP_DST_PORT = TCP_SRC_PORT + TCP_PORT_LEN;
	
	//variables
	public int source_port;
	public int destination_port;

	public TCPPacket(byte[] packet) {
		super(packet);
		this.packet_type = "tcp";
		parse();
	}//end constructor
	
	public String toString() {
		String out = super.toString();
		
		out+=outln("Source Port: "+source_port);
		out+=outln("Destination Port: "+destination_port);
		
		return out;
	}//end toString
	
	public boolean is_type(String type){
		return ( type.equals("all") || type.equals("eth") || type.equals("ip") || type.equals("tcp") );
	}//end is_type
	
	private void parse(){
		byte[] srcP = new byte[4];
		byte[] dstP = new byte[4];
		
        System.arraycopy(packet, TCP_SRC_PORT, srcP, 2, TCP_PORT_LEN);
        System.arraycopy(packet, TCP_DST_PORT, dstP, 2, TCP_PORT_LEN);
        
        source_port = bytesToInt(srcP);
        destination_port = bytesToInt(dstP);
	}//end parse

	public TCPPacket port_filter(Integer source_port_start,
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

}//end TCPPacket