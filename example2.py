import pyshark
import netifaces


intF = netifaces.gateways()['default'][netifaces.AF_INET][1]#Find the interface w/ the default gateway.
capture = pyshark.LiveCapture(interface=intF,bpf_filter="tcp and port 80")#tshark filter 
#visit http://example.com
#during the capture.

for packet in capture.sniff_continuously():
    if (hasattr(packet,'highest_layer') and packet.highest_layer == 'HTTP'):
        #we should be past the 3-way handshake.  
        #converting PayLoad(hex) to string and print.
 
        tempStr = str(packet.tcp.payload)
        HexPayload = tempStr.replace(':','')#remove colons
        byte_string = bytes.fromhex(HexPayload)
        result = byte_string.decode('utf-8')
        print(result)#the payload should be printed.

        #going through http layer and printing items.
        if hasattr(packet,'accept_encoding'):
            #print it
            print(packet.layers[3].accept_encoding)
        if hasattr(packet,'layer_name'):
            #
            print(packet.layers[3].layer_name)
