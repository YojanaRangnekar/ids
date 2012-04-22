
public class ICMPPacket extends IPPacket{

	//ICMP packet locations
	final int ICMP_PACKET_START = IP_PAYLOAD_START;
	
	final int ICMP_TYPE_LEN = (int)(8/BITS_IN_BYTE);
	final int ICMP_CODE_LEN = (int)(8/BITS_IN_BYTE);
	final int ICMP_CHECKSUM_LEN = (int)(16/BITS_IN_BYTE);
	
	final int ICMP_TYPE = ICMP_PACKET_START;
	final int ICMP_CODE = ICMP_TYPE+ICMP_TYPE_LEN;
	final int ICMP_CHECKSUM = ICMP_CODE+ICMP_CODE_LEN;
	
	//variables
	public int icmp_type;
	public int icmp_code;
	public int icmp_checksum;

	public ICMPPacket(byte[] packet) {
		super(packet);
		this.packet_type = "icmp";
		parse();
	}//end constructor
	
	public String toString() {
		String out = super.toString();
		
		out+=outln("Type: "+icmp_type);
		out+=outln("Code: "+icmp_code);
		
		return out;
	}//end toString
	
	public boolean is_type(String type){
		return ( type.equals("all") || type.equals("eth") || type.equals("ip") || type.equals("icmp") );
	}//end is_type
	
	private void parse(){
		byte[] type = new byte[1];
		byte[] code = new byte[1];
		
        System.arraycopy(packet, ICMP_TYPE, type, 0, ICMP_TYPE_LEN);
        System.arraycopy(packet, ICMP_CODE, code, 0, ICMP_CODE_LEN);
        
        icmp_type = unsignedByteToInt(type[0]);
        icmp_code = unsignedByteToInt(code[0]);
	}//end parse

}//end ICMPPacket