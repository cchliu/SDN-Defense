""" 
    No. of distinct unique 5-tuples (micro flow_id, sid) 
    No. of alerts
    No. of distinct SIDs triggered
"""
import csv
import os
import glob

### Total number of alerts triggered
def count_alerts(result):
    return len(result)

### 5tuple only considers proto, src_ip, src_port, dst_ip, dst_port
def count_unique_5tuple_simple(result):
    mapping = {}
    for line in result:
        proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
        tmp_string = ' '.join([proto, src_ip, src_port, dst_ip, dst_port, sid])
        if not tmp_string in mapping:
            mapping[tmp_string] = 1
    return len(mapping.keys())

### Distinct flows: unique 5-tuples + (micro_flow_id, direction, sid)
def count_unique_flows(result):
    mapping = {}
    for line in result:
        proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
        micro_flow_id, direction, pos_in_flow, flow_lenth = line[-4:]
        tmp_string = ' '.join([proto, src_ip, src_port, dst_ip, dst_port, micro_flow_id, direction, sid])
        if not tmp_string in mapping:
            mapping[tmp_string] = 1
    return len(mapping.keys())

### Total number of SIDs triggered 
def count_distinct_SIDs(result):
    mapping = {}
    for line in result:
        proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
        if not sid in mapping:
            mapping[sid] = 1
    return len(mapping.keys())

def stats_1(infiles, postfix):
    result = []
    for tmp_file in infiles:
        with open(tmp_file, 'rb') as ff:
            reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
            for line in reader:
                result.append(line)

    # extract out tcp/udp alerts
    result = [line for line in result if line[0] == 'tcp' or line[0] == 'udp']
    print "Number of alerts triggered: ", count_alerts(result)
    print "Number of unique 5-tuples (micro flow_id, direction, sid): ", count_unique_flows(result)
    print "Number of distinct SIDs triggered: ", count_distinct_SIDs(result)    
    #table_sid_frequency(result, postfix)

    tcp_result = [line for line in result if line[0] == 'tcp']
    print "Number of TCP alerts triggered: ", count_alerts(tcp_result)
    print "Number of unique 5-tuples (micro flow_id, direction, sid) triggering TCP alerts: ", count_unique_flows(tcp_result)
    print "Number of distinct SIDs triggered in TCP alerts: ", count_distinct_SIDs(tcp_result)

    udp_result = [line for line in result if line[0] == 'udp']
    print "Number of UDP alerts triggered: ", count_alerts(udp_result)
    print "Number of unique 5-tuples (micro flow_id, direction, sid) triggering UDP alerts: ", count_unique_flows(udp_result)
    print "Number of distinct SIDs triggered in UDP alerts: ", count_distinct_SIDs(udp_result)


def main():
    #log_dir = '/home/cchliu/data/log/wifi/0530'
    log_dir = '/home/chang/tmp/alerts'
    files_lst = glob.glob('{0}/*.csv'.format(log_dir))
    stats_1(files_lst, '0530')

if __name__ == "__main__":
    main()
    
