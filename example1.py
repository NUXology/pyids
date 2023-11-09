import pyshark
import netifaces
import ipaddress
import json
import requests
import base64

class pckt(object):
    def __init__(self,sniff_timestamp:str='',layer:str='',srcPort:str='',dstPort:str='',ipSrc:str='',ipDst:str='',highest_layer=''):
        self.sniff_timestamp = sniff_timestamp
        self.layer = layer
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.highest_layer = highest_layer

class apiServer(object):
    def __init__(self,ip:str,port:str):
        self.ip = ip
        self.port = port


server = apiServer('192.168.2.132','8080')

#Default interface [AF_INET] AddressFamily IPv4
intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)



def report(message:pckt):
    temp = json.dumps(message.__dict__)
    
    jsonString = temp.encode('ascii')
    b64 = base64.b64encode(jsonString)

    jsonPayload = b64.decode('utf8').replace("'",'"')
    print(jsonString)

    try:
        #
        x = requests.get('http://{}:{}/api/?{}'.format(server.ip,server.port,str(jsonPayload)))
    except err as ConnectionError:
        #
        #do Logging
        pass

def is_api_server(packet:capture,server:apiServer)->bool:
    #is the packet to our api_server
    #
    if (hasattr(packet,'ip') and (hasattr(packet,'tcp'))):
        if ((packet.ip.src == server.ip) or (packet.ip.dst == server.ip)) and ((packet.tcp.dstport == server.port) or (packet.tcp.srcport == server.port)):
            return True
    
    else:
        
        return False
       

def is_private_ip(ip_address):
    '''
    Determines if the given ip address is private
    
    Args:
        ip_address: The IP to Check

    Returns:
        True if the ip is private

    
    '''
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def packetFilter(packet:capture):
    '''
    Filters the packet
    '''
    #are we talking to the apiServer to report?
    if is_api_server(packet,server) is True:
        #then do not proceed in reporting
        #bail out
        return
    
    if hasattr(packet,'icmp'):
        #we've just been pinged.
        p = pckt()
        p.ipDst = packet.ip.dst
        p.ipSrc = packet.ip.src
        p.highest_layer = packet.highest_layer
        #print('pinged.')
        report(p)
        return
    if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
        if hasattr(packet,'ipv6'):
            #has different fields than ipv4
            #Disabled ipv6 in grub
            if hasattr(packet,'MDNS'):
                #Ignore MDNS
                return None
            if hasattr(packet,'DHCPV6'):
                #Ignore DHCPV6
                return None
            if hasattr(packet,'SSDP'):
                #Ignore SSDP
                return None
            if hasattr(packet,'LLMNR'):
                #ignore LLMNR
                return None
            else:
                #report
                print(packet)
                pass
            
        if hasattr(packet,'ip'):
            #has different fields than ipv6
            if (is_private_ip(packet.ip.src) is True) and (is_private_ip(packet.ip.dst) is True):
                #we've got local communication
                p = pckt()

                #source ip
                p.ipSrc = packet.ip.src
                #Destination IP
                p.ipDst = packet.ip.dst

                p.sniff_timestamp = packet.sniff_timestamp

                p.highest_layer = packet.highest_layer

                if hasattr(packet,'UDP') is True:
                    p.dstPort = packet.udp.dstport
                    p.srcPort = packet.udp.srcport
                    p.layer = packet.transport_layer
                if hasattr(packet,'TCP') is True:
                    p.dstPort = packet.tcp.dstport
                    p.srcPort = packet.tcp.srcport
                    p.layer = packet.transport_layer
                report(p)
                return

for packet in capture.sniff_continuously():
    #filter out packet
    packetFilter(packet)