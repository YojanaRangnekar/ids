import java.net.InetAddress;
import java.net.UnknownHostException;


public class IPPacket extends EthernetPacket {
	
	//http://www.tcpipguide.com/free/t_IPDatagramGeneralFormat.htm
	
	final int MAX_HEADER_SIZE = 60 + ETHER_PAYLOAD_START;
	
	//ipv4 packet locations
	final int IP_PACKET_START = ETHER_PAYLOAD_START;
	
	final int IP_VER_HL_LEN = 1;
	
	//Identification
	final int IP_LENGTH = IP_PACKET_START + (int)(16/BITS_IN_BYTE);
	final int IP_LENGTH_LEN = 2;
	//Identification
	final int IP_IDENT = IP_PACKET_START + (int)(32/BITS_IN_BYTE);
	final int IP_IDENT_LEN = 2;
	//Flags+Fragment Offset
	final int IP_FLAG_FRAG = IP_PACKET_START + (int)(48/BITS_IN_BYTE);
	final int IP_FLAG_FRAG_LEN = 2;
	final int FRAG_OFFSET_MULT = 8;
	//TTL
	final int IP_TTL = IP_PACKET_START + (int)(64/BITS_IN_BYTE);
	final int IP_TTL_LEN = 1;
	//Protocol
	final int IP_PROTOCOL_TYPE = IP_PACKET_START + (int)(72/BITS_IN_BYTE); //14+9=23
	final int IP_PROTOCOL_TYPE_LEN = 1;
	//Src/Dst Addr
	final int IP_SRC = IP_PACKET_START + (int)(96/BITS_IN_BYTE); //14+12=26
	final int IP_ADDR_LEN = 4;
	final int IP_DST = IP_SRC + IP_ADDR_LEN; //14+16=30
	
	int IP_PAYLOAD_START;
	int IP_PAYLOAD_END;
	
	//ip protocols
	final String TCP = "06";
	final String UDP = "11";
	final String ICMP = "01";
	
	//private variables
	public int header_length_bytes;
	
	public int total_length;
	public int identification;
	public String flags_and_fragment_offset;
	public String flags;
	public int fragment_offset;
	public int time_to_live;
	
	//values for fragment reassembly
	public int data_length;
	public int first;
	public int last;
	
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
		out+=outln("Total Length: "+total_length);
		out+=outln("Data Length: "+data_length); 
		out+=outln("Identification: "+identification);
		out+=outln("FlagFrag Binary: "+flags_and_fragment_offset);
		out+=outln("Flags: "+flags);
		out+=outln("Last Fragment?: "+this.isLastFragment());
		out+=outln("Fragment Offset: "+fragment_offset);
		out+=outln("First octet: "+first);
		out+=outln("Last octet: "+last);
		out+=outln("TTL: "+time_to_live);
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
		byte[] verHL = new byte[IP_VER_HL_LEN];
		byte[] length = new byte[IP_LENGTH_LEN];
		byte[] ident = new byte[IP_IDENT_LEN];
		byte[] flagFrag = new byte[IP_FLAG_FRAG_LEN];
		byte[] ttl = new byte[IP_TTL_LEN];
		byte[] ipProt = new byte[IP_PROTOCOL_TYPE_LEN];
		byte[] srcAddr = new byte[IP_ADDR_LEN];
		byte[] dstAddr = new byte[IP_ADDR_LEN];
		
        System.arraycopy(packet, IP_PACKET_START, verHL, 0, IP_VER_HL_LEN);
        String verHLStr = driver.byteToHex(verHL[0]);
        header_length_bytes = calcHeaderLength(verHLStr.charAt(1));
        
        
        System.arraycopy(packet, IP_LENGTH, length, 0, IP_LENGTH_LEN);
        total_length = bytesToDecimal(length);
        data_length = total_length - header_length_bytes;
        System.arraycopy(packet, IP_IDENT, ident, 0, IP_IDENT_LEN);
        identification = bytesToDecimal(ident);
        System.arraycopy(packet, IP_FLAG_FRAG, flagFrag, 0, IP_FLAG_FRAG_LEN);
        parseFlagFrag(flagFrag);
        System.arraycopy(packet, IP_TTL, ttl, 0, IP_TTL_LEN);
        time_to_live = bytesToDecimal(ttl);
        //toBitString
        
        
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

	private void parseFlagFrag(byte[] flagFrag) {
		String binaryFlagFrag = bytesToBinary(flagFrag);
		flags_and_fragment_offset = binaryFlagFrag;
		
		flags = binaryFlagFrag.substring(0, 3);
		fragment_offset = Integer.parseInt(binaryFlagFrag.substring(3), 2);
		
		first = (fragment_offset * FRAG_OFFSET_MULT);
		last = (fragment_offset * FRAG_OFFSET_MULT) + data_length;
	}//end parseFlagFrag
	
	public boolean isLastFragment(){
		return flags.charAt(2)=='0';
	}//end isLastFragment
	
	public boolean isFirstFragment(){
		return fragment_offset==0;
	}//end isLastFragment

	private int calcHeaderLength(char headLenChar) {
		String headLenStr = String.valueOf(headLenChar);
		int headLenVal = Integer.parseInt(headLenStr, 16);
		//heaadLenVal = number of 32-bit words or 4 bytes
		return headLenVal * 4; //return byte length of header
	}//end calcHeaderLength
	
	public byte[] getData(){
		byte[] packetData = new byte[data_length];
		System.arraycopy(packet, IP_PAYLOAD_START, packetData, 0, data_length);
		return packetData;
	}//end getData

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
