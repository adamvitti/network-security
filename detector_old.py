from scapy.all import *
from scapy.all import TCP,IP,Ether,Raw
import sys


class Anamoly:
    def __init__(self, ip: str, syn_counter: int = 0, syn_ack_counter: int = 0) -> None:
        self.ip = ip
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
syn_pkts = [] #number of syns an IP sends
syn_ack_pkts = [] #number of syn_acks an IP recieves 
packet_ips_syn = []
packet_ips_syn_ack = []
sus_pkts = [] #will populate with the ips that are sus
def process_pcap(pcap_fname):
    for pkt in PcapReader(pcap_fname):
        if pkt.haslayer(TCP):
            if str(pkt[TCP].flags) == syn_flag: #track syn count for each ip
                if pkt[IP].src not in packet_ips_syn:
                    packet_ips_syn.append(pkt[IP].src) #keep record of which ips we have added to dict
                    new_syn_dic = {pkt[IP].src: 0} #new syn record for ip 
                    syn_pkts.append(new_syn_dic)
                #check if ip has already been recorded 
                index = 0
                for dic in syn_pkts:
                    for ip, counter in dic.items():
                        if ip == pkt[IP].src: #already have it in the array, simply increment counter
                            syn_pkts[index][ip] = counter + 1
                        
                    index = index + 1

            # print(pkt[TCP].flags)
            if str(pkt[TCP].flags) == syn_ack_flag:
                if pkt[IP].dst not in packet_ips_syn_ack:
                    packet_ips_syn_ack.append(pkt[IP].dst) #keep record of which ips we have added to dict
                    new_syn_ack_dic = {pkt[IP].dst: 0} #new syn_ack record for ip 
                    syn_ack_pkts.append(new_syn_ack_dic)
                #check if ip has already been recorded 
                index = 0
                for dic in syn_ack_pkts:
                    for ip, counter in dic.items():
                        if ip == pkt[IP].src: #already have it in the array, simply increment counter
                            syn_ack_pkts[index][ip] = counter + 1
                        
                    index = index + 1
    # Constructed array of syn acks and syn_acks now need to compare their counters by taking difference...
    index = 0
    for dic in syn_pkts:
        for ip, counter1 in dic.items():
            index2 = 0
            for dic2 in syn_ack_pkts:
                for ip2, counter2 in dic2.items():
                    if ip == ip2:
                        diff = syn_pkts[index][ip] - syn_ack_pkts[index2][ip2]
                        if diff >= 3:
                            print(ip)
                index2 = index2 + 1
            
        index = index + 1
    # print('ips:')
    # print(packet_ips_syn)
    # print(packet_ips_syn_ack)
    print('dics')
    print(syn_pkts)
    print(syn_ack_pkts)
    pass

if __name__=='__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
