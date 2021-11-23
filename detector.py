from scapy.all import *
from scapy.all import TCP,IP,Ether,Raw
import sys


class Anamoly:
    def __init__(self, ip: str, syn_counter: int, syn_ack_counter: int) -> None:
        self._ip = ip
        self._syn_counter = syn_counter
        self._syn_ack_counter = syn_ack_counter
    
    @property
    def ip(self):  # Getter
        return self._ip
    @property
    def syn_counter(self):  # Getter
        return self._syn_counter
    @property
    def syn_ack_counter(self):  # Getter
        return self._syn_ack_counter

    @syn_counter.setter
    def syn_counter(self, syn_counter):  # Setter
        self._syn_counter = syn_counter
    @syn_ack_counter.setter
    def syn_ack_counter(self, syn_ack_counter):  # Setter
        self._syn_ack_counter = syn_ack_counter

# Complete this function!
syn_flag = 'S'#0x002
syn_ack_flag = 'SA'#0x012
anamoly_arr = []
packet_ips = []
sus_pkts = [] #will populate with the ips that are sus
def process_pcap(pcap_fname):
    for pkt in PcapReader(pcap_fname):
        if pkt.haslayer(TCP):
                if str(pkt[TCP].flags) == syn_flag: #track syn count for each ip
                    if pkt[IP].src not in packet_ips: #not added yet
                        packet_ips.append(pkt[IP].src) #keep record of which ips we have added to dict
                        new_anamoly = Anamoly(pkt[IP].src, 1, 0) #new syn record for ip 
                        anamoly_arr.append(new_anamoly)
                    else: #already added
                        for anamoly in anamoly_arr:
                            if anamoly.ip == pkt[IP].src: #already have it in the array, simply increment counter
                                anamoly.syn_counter += 1

                if str(pkt[TCP].flags) == syn_ack_flag: #track syn ack count for each ip
                    if pkt[IP].dst not in packet_ips: #not added yet
                        packet_ips.append(pkt[IP].dst) #keep record of which ips we have added to dict
                        new_anamoly = Anamoly(pkt[IP].dst, 0, 1) #new syn record for ip 
                        anamoly_arr.append(new_anamoly)
                    else:
                        for anamoly in anamoly_arr:
                            if anamoly.ip == pkt[IP].dst: #already have it in the array, simply increment counter
                                anamoly.syn_ack_counter += 1

    #check difference between syn and syn_ack
    for anamoly in anamoly_arr:
        if anamoly.syn_counter != 0 and anamoly.syn_ack_counter == 0: # any packets that dont recieve a syn-ack considered sus 
            print(anamoly.ip)
            # diff = anamoly.syn_counter - anamoly.syn_ack_counter # 3 or more syns than acks 
            # if diff >= 3: 
            #     print(anamoly.ip)
        else:
            div = anamoly.syn_counter / anamoly.syn_ack_counter
            if div >= 3: # 3 or more times as many syns
                print(anamoly.ip)

        # if anamoly.ip == '192.168.0.15' or anamoly.ip == '128.3.164.249':
        #     print(anamoly.ip, anamoly.syn_counter, anamoly.syn_ack_counter)
    # print('ips:')
    # print(packet_ips_syn)
    # print(packet_ips_syn_ack)
    # print('dics')
    # print(syn_pkts)
    # print(syn_ack_pkts)
    pass

if __name__=='__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
