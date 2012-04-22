import java.net.InetAddress;
import java.net.UnknownHostException;


public class IPPacket extends EthernetPacket {
	
	//http://www.tcpipguide.com/free/t_IPDatagramGeneralFormat.htm
	
	//ipv4 packet locations
	final int IP_PACKET_START = ETHER_PAYLOAD_START;
	
	final int IP_VER_HL_LEN = 1;
	
	final int IP_PROTOCOL_TYPE = IP_PACKET_START + (int)(72/BITS_IN_BYTE); //14+9=23
	final int IP_PROTOCOL_TYPE_LEN = 1;
	
	final int IP_SRC = IP_PACKET_START + (int)(96/BITS_IN_BYTE); //14+12=26
	final int IP_ADDR_LEN = 4;
	final int IP_DST = IP_SRC + IP_ADDR_LEN; //14+16=30
	
	int IP_PAYLOAD_START;
	
	//ip protocols
	final String TCP = "06";
	final String UDP = "11";
	final String ICMP = "01";
	
	//private variables
	public int header_length_bytes;
	public String protocol;
	public InetAddress source_ip;
	public InetAddress destination_ip;

	public IPPacket(byte[] packet) {
		super(packet);
		this.packet_type = "ip";
		parse();
	}//end constructor
	
	public String toString() {
		String out = super.toString();
		
		out+=outln("Header Length: "+header_length_bytes);
		out+=outln("Payload Start: "+IP_PAYLOAD_START);
		out+=outln("Protocol: "+protocol);
		out+=outln("Source Address: "+source_ip);
		out+=outln("Destination Address: "+destination_ip);
		
		return out;
	}//end toString
	
	public boolean is_type(String type){
		return ( type.equals("all") || type.equals("eth") || type.equals("ip") );
	}//end is_type
	
	private void parse(){
		byte[] verHL = new byte[1];
		byte[] ipProt = new byte[1];
		byte[] srcAddr = new byte[4];
		byte[] dstAddr = new byte[4];
		
        System.arraycopy(packet, IP_PACKET_START, verHL, 0, IP_VER_HL_LEN);
        String verHLStr = driver.byteToHex(verHL[0]);
        header_length_bytes = calcHeaderLength(verHLStr.charAt(1));
        IP_PAYLOAD_START = IP_PACKET_START + header_length_bytes;
        
        System.arraycopy(packet, IP_PROTOCOL_TYPE, ipProt, 0, IP_PROTOCOL_TYPE_LEN);
        String ipProtNum = getHexString(ipProt);
        if(ipProtNum.equals(TCP)){
        	protocol = "TCP";
        }else if(ipProtNum.equals(UDP)){
        	protocol = "UDP";
        }else if(ipProtNum.equals(ICMP)){
        	protocol = "ICMP";
        }else{
        	protocol = "Unrecognized IP protocol: "+ipProtNum;
        }
        
        System.arraycopy(packet, IP_SRC, srcAddr, 0, IP_ADDR_LEN);
        System.arraycopy(packet, IP_DST, dstAddr, 0, IP_ADDR_LEN);
        try {
			destination_ip = InetAddress.getByAddress(dstAddr);
			source_ip = InetAddress.getByAddress(srcAddr);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}//end try/catch
        
        
	}//end parse

	private int calcHeaderLength(char headLenChar) {
		String headLenStr = String.valueOf(headLenChar);
		int headLenVal = Integer.parseInt(headLenStr, 16);
		//heaadLenVal = number of 32-bit words or 4 bytes
		return headLenVal * 4; //return byte length of header
	}//end calcHeaderLength

	public IPPacket address_filter(InetAddress source_address,
			InetAddress destination_address, InetAddress OR_source_address,
			InetAddress OR_destination_address, InetAddress AND_source_address,
			InetAddress AND_destination_address) {
		if(source_ip.equals(source_address)) return this;
		if(destination_ip.equals(destination_address)) return this;
		if(source_ip.equals(OR_source_address) || destination_ip.equals(OR_destination_address)) return this;
		if(source_ip.equals(AND_source_address) && destination_ip.equals(AND_destination_address)) return this;
		
		return null;
	}//end address_filter


}//end IPPacket
