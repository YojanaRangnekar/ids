
public class EthernetPacket extends GenericPacket {
	
	//Helper variables
	final int BITS_IN_BYTE = 8;
	
	final int ETHER_MAC_DST = 0;
	final int ETHER_MAC_SRC = 6;
	final int ETHER_MAC_LEN = 6;
	final int ETHER_TYPE = 12;
	final int ETHER_TYPE_LEN = 2;
	
	final int ETHER_PAYLOAD_START = 14;
	
	final int HEX_PAIRS_PER_LINE_OUTPUT = 16;
	
	//Ethertypes
	final String IPV4 = "0800";
	final String ARP = "0806";
	
	
	
	//variables
	public static SimplePacketDriver driver;
	public byte[] packet;
	
	public byte[] destination_mac;
	public byte[] source_mac;
	public String ethertype;

	public EthernetPacket(byte[] packet) {
		this.driver = new SimplePacketDriver();
		this.packet = packet;
		this.packet_type = "eth";
		parse();
	}//end constructor
	
	public String toString() {
		String out = "";
		out += outln("Source MAC: "+hardwareAddrToPrintString(source_mac));
		out += outln("Destination MAC: "+hardwareAddrToPrintString(destination_mac));
		out += outln("EtherType: "+ethertype);
		
		return out;
	}//end toString
	
	public boolean is_type(String type){
		return ( type.equals("all") || type.equals("eth") );
	}//end is_type

	private void parse() {
		byte[] dst = new byte[6];
		byte[] src = new byte[6];
		byte[] typ = new byte[2];
		
        System.arraycopy(packet, ETHER_MAC_DST, dst, 0, ETHER_MAC_LEN);
        destination_mac = dst;
        
        System.arraycopy(packet, ETHER_MAC_SRC, src, 0, ETHER_MAC_LEN);
        source_mac = src;
        
        System.arraycopy(packet, ETHER_TYPE, typ, 0, ETHER_TYPE_LEN);
        String eth_typ = getHexString(typ);
        if(eth_typ.equals(IPV4)){
        	ethertype = "IPv4";
        }else if(eth_typ.equals(ARP)){
        	ethertype = "ARP";
        }else{
        	ethertype = "Unrecognized EtherType: "+eth_typ;
        }
        
	}//end parse
	
	public String toHexBlock(){
		String hexBlock = "";

		for (int i = 0; i < packet.length; i++) {
			
			if(i%HEX_PAIRS_PER_LINE_OUTPUT==0){
				hexBlock+="\n";
			}
			//convert byte to hex pair
			hexBlock += driver.byteToHex(packet[i]).toLowerCase()+" ";
			
		}//end for each byte in packet
		hexBlock+="\n";
		
		return hexBlock;
	}//end outputAsHexBlock
	
	public String outln(String str){
		return str+"\n";
	}//end outln
	
	public static String getHexString(byte[] b) {
		  String result = "";
		  for (int i=0; i < b.length; i++) {
		    result += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
		  }
		  return result;
	}//end getHexString
	
	public static int bytesToInt(byte[] data) {
		if (data == null || data.length != 4) return 0x0;
		// ----------
		return (int)( // NOTE: type cast not necessary for int
		(0xff & data[0]) << 24 |
		(0xff & data[1]) << 16 |
		(0xff & data[2]) << 8 |
		(0xff & data[3]) << 0
		);
	}//end bytesToInt
	
	public static int unsignedByteToInt(byte b) {
	    return (int) b & 0xFF;
    }//end unsignedByteToInt
	
	public static String hardwareAddrToPrintString(byte[] b){
		return driver.byteArrayToString(b).substring(0,17).replace(" ", "-");
	}//end byteArrayToPrintString

}//end EthernetPacket