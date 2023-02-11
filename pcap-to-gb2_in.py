import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def process_pcap(pcap_file_name):
    count = 0
    tcp_ip_pkt_count = 0
    ack_only_pkt_count = 0
    flow_list = []
    pkt_id_list = [0*200]
    weight = 1

    #base_start_sec = 0;
    last_start_usec = -1;
    usec_to_clk = 1;
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file_name):
        count += 1
        #print('Debug pkt_data {}'.format(pkt_data))
        #print('Debug pkt_metadata {}'.format(pkt_metadata))
        #print('sec {}'.format(pkt_metadata.sec))
        #print('usec {}'.format(pkt_metadata.usec))
        #print('[prior]last_start_usec = {}'.format(last_start_usec))
        if last_start_usec == -1:
            usec_delay = 0;
        else: 
            usec_delay = pkt_metadata.usec - last_start_usec
        last_start_usec = pkt_metadata.usec
        #print('[after]last_start_usec = {}'.format(last_start_usec))
        clk_delay = int (usec_delay / usec_to_clk)


        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        
#       if ip_pkt.proto != 6 and ip_pkt.proto != 17:
        if ip_pkt.proto != 6:
            # Ignore non-TCP and non-UDP packet
            continue

        tcp_pkt = ip_pkt[TCP]

        pkt_len = max(len(ether_pkt), 64)    
        fin_time = pkt_len/weight

        five_tuple = (ip_pkt.src, tcp_pkt.sport, ip_pkt.dst, tcp_pkt.dport, ip_pkt.proto);
        try:
           	# get flow_id for 5-tuple
            flow_id = flow_list.index(five_tuple)
            # get and update pkt_id for flow 
            pkt_id = pkt_id_list[flow_id]
            pkt_id += 1
            pkt_id_list[flow_id] = pkt_id
        except ValueError:
            flow_list.append(five_tuple)
            flow_id = flow_list.index(five_tuple)
            pkt_id_list.append(1)
            pkt_id = 1

            '''# get flow_id for 5-tuple
            flow_id = flow_list.index(five_tuple)
            #flow_id = 0
            # get and update pkt_id for flow 
            pkt_id = pkt_id_list[flow_id]
            pkt_id += 1
            pkt_id_list[flow_id] = pkt_id
        except ValueError:
            flow_list.append(five_tuple)
            pkt_id_list.append(1)'''        
            
        desc_tuple = (pkt_len, fin_time, (flow_id, pkt_id))
        ##self.pcap_desc_pipe.put(desc_tuple)
        ##pkt_time = self.PREAMBLE + pkt_len + self.IFG
        ##yield self.wait_line_clks(pkt_time)
        #print('{}'.format(desc_tuple))
        print('V {} {} {} {} {}'.format(clk_delay, pkt_len, fin_time, flow_id, pkt_id))


    #print('{} contains {} packets ({} TCP/IP packets)'.
    #      format(file_name, count, tcp_ip_pkt_count))
          
    #print('There are {} flows'.format(len(flow_list)))
    #print('There are {} ack only packets'.format(ack_only_pkt_count))

process_pcap("test.pcap")
