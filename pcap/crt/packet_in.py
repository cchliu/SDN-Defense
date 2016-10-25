""" 
    Different packets will be forwarded to the 
    controller at different choice of K;
    v2: condense across different pcap files 
"""
import csv
import os

GLOBAL_HEADER = 24
PACKET_HEADER = 16

def packet_in(pcap_file, pcap_csv_file, out_dir, K):
    f_in = open(pcap_file[0], 'rb')
    data = f_in.read(GLOBAL_HEADER) 
    f_in.close()

    count = 0    
    flow_table = {}
    for i in range(len(pcap_file)):
        tmp_pcap = pcap_file[i]
        tmp_pcap_csv = pcap_csv_file[i]
        f_in = open(tmp_pcap, 'rb')
        f_in.read(GLOBAL_HEADER)

        with open(tmp_pcap_csv, 'rb') as ff:
            reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
            for line in reader:
                frame_number, frame_time, frame_time_epoch, frame_lenth, frame_proto, src_ip, dst_ip, \
                src_udp_port, dst_udp_port, src_tcp_port, dst_tcp_port, tcp_flags_syn, tcp_flags_ack, tcp_flags_fin = line[:14]
                tmp_data = f_in.read(PACKET_HEADER + int(frame_lenth))
                if 'udp' in frame_proto:
                    tmp_proto = 'udp'
                    tmp_src_port = src_udp_port
                    tmp_dst_port = dst_udp_port
                elif 'tcp' in frame_proto:
                    tmp_proto = 'tcp'
                    tmp_src_port = src_tcp_port
                    tmp_dst_port = dst_tcp_port
                else:
                    continue
                tmp_string = ' '.join([tmp_proto, src_ip, tmp_src_port, dst_ip, tmp_dst_port])
                # For simplicity, only interested in TCP flows
                if tmp_proto == 'tcp':
                    if not tmp_string in flow_table:
                        flow_table[tmp_string] = 1
                    else:
                        flow_table[tmp_string] += 1
                    if flow_table[tmp_string] <= K:
                        data += tmp_data
                        count += 1
        f_in.close()    
    
    filename = os.path.basename(out_dir)
    outfile = os.path.join(out_dir, filename + '_{0}'.format(K))
    print outfile, "number of packets: {0}".format(count)
    with open(outfile, 'wb') as ff:
        ff.write(data)


