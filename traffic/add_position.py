"""
    For each pkt, add micro_flow_id, position_in_flow, direction
    & the micro_flow_size
"""
import csv
import os
import math
from subprocess import call
from multiprocessing import Process, Queue
import helpers
import settings

def add_micro_flow_size(result):
    # calculate micro_flow_size
    mapping = {}
    for line in result:
        # parse the line
        frame_number, frame_time, frame_time_epoch, frame_lenth, frame_proto, src_ip, dst_ip, src_udp_port, dst_udp_port, src_tcp_port, dst_tcp_port, tcp_flags_syn, tcp_flags_ack = line[:13]
        micro_flow_id = str(line[-3])
        if 'udp' in frame_proto:
            tmp_proto = 'udp'
            tmp_src_port = src_udp_port
            tmp_dst_port = dst_udp_port
        elif 'tcp' in frame_proto:
            tmp_proto = 'tcp'
            tmp_src_port = src_tcp_port
            tmp_dst_port = dst_tcp_port
        else:
            #TODO: other than udp/tcp, what will be other transport protocol?
            continue
        tmp_string = tmp_proto + ' ' + src_ip + ' ' + dst_ip + ' ' + tmp_src_port + ' ' + tmp_dst_port + ' ' + micro_flow_id
        if not tmp_string in mapping:
            mapping[tmp_string] = 0
        #if 'tcp' in tmp_proto:
        #   mapping[tmp_string] += 1
        mapping[tmp_string] += 1

    # add micro_flow_size
    new_result = []
    for line in result:
        # parse the line
        frame_number, frame_time, frame_time_epoch, frame_lenth, frame_proto, src_ip, dst_ip, src_udp_port, dst_udp_port, src_tcp_port, dst_tcp_port, tcp_flags_syn, tcp_flags_ack = line[:13]
        micro_flow_id = str(line[-3])
        if 'udp' in frame_proto:
            tmp_proto = 'udp'
            tmp_src_port = src_udp_port
            tmp_dst_port = dst_udp_port
        elif 'tcp' in frame_proto:
            tmp_proto = 'tcp'
            tmp_src_port = src_tcp_port
            tmp_dst_port = dst_tcp_port
        else:
            #TODO: other than udp/tcp, what will be other transport protocol?
            continue
        tmp_string = tmp_proto + ' ' + src_ip + ' ' + dst_ip + ' ' + tmp_src_port + ' ' + tmp_dst_port + ' ' + micro_flow_id
        tmp_row = line + [mapping[tmp_string]]
        new_result.append(tmp_row)

    return new_result

def worker(sublist, out_q, thread_id):
    num_of_files = len(sublist)
    count = 0

    tmp_proto, tmp_src_port, tmp_dst_port = 0, 0, 0
    for tmp_file in sublist:
        count += 1

        mapping = {}
        result = []
        with open(tmp_file, 'rb') as ff:
            reader = csv.reader(ff, delimiter='\t', quoting = csv.QUOTE_NONE)
            for line in reader:
                # parse the line
                frame_number, frame_time, frame_time_epoch, frame_lenth, frame_proto, src_ip, dst_ip, src_udp_port, dst_udp_port, src_tcp_port, dst_tcp_port, tcp_flags_syn, tcp_flags_ack = line[:13]
                if 'udp' in frame_proto:
                    tmp_proto = 'udp'
                    tmp_src_port = src_udp_port
                    tmp_dst_port = dst_udp_port
                elif 'tcp' in frame_proto:
                    tmp_proto = 'tcp'
                    tmp_src_port = src_tcp_port
                    tmp_dst_port = dst_tcp_port
                else:
                    #TODO: other than udp/tcp, what will be other transport protocol?
                    continue
                tmp_string = tmp_proto + ' ' + src_ip + ' ' + dst_ip + ' ' + tmp_src_port + ' ' + tmp_dst_port
                
                if not tmp_string in mapping:
                    mapping[tmp_string] = {}
                    mapping[tmp_string]['curr_pos_in_flow'] = -100
                    mapping[tmp_string]['micro_flow_id'] = -1
                    mapping[tmp_string]['direction'] = -100
                # calculate pos_in_flow, micro_flow_id, and direction   
                # direction 0: from client to server
                # direction 1: from server to client
                curr_pos_in_flow = mapping[tmp_string]['curr_pos_in_flow']
                micro_flow_id = mapping[tmp_string]['micro_flow_id']
                direction = mapping[tmp_string]['direction']
                ### add pos_in_flow for udp flows
                if tmp_proto == 'udp':
                    if curr_pos_in_flow < 0:
                        curr_pos_in_flow = 0
                    else:
                        curr_pos_in_flow += 1

                ### add pos_in_flow for tcp flows
                if tmp_proto == 'tcp':
                    if tcp_flags_syn == '1' and tcp_flags_ack == '0':
                        curr_pos_in_flow = 0
                        direction = 0
                        micro_flow_id += 1
                    elif tcp_flags_syn == '1' and tcp_flags_ack == '1':
                        curr_pos_in_flow = 0
                        direction = 1
                        micro_flow_id += 1
                    elif curr_pos_in_flow >= 0:
                        curr_pos_in_flow += 1
                    else:
                        curr_pos_in_flow = -100
                        micro_flow_id = -1
                        direction = -100
                tmp_row = line + [micro_flow_id, direction, curr_pos_in_flow]
                
                # update entries in mapping
                mapping[tmp_string]['curr_pos_in_flow'] = curr_pos_in_flow
                mapping[tmp_string]['micro_flow_id'] = micro_flow_id
                mapping[tmp_string]['direction'] = direction
                    
                # save the updated row
                result.append(tmp_row)      

        # add micro_flow_size
        result = add_micro_flow_size(result)
        
        # write updated rows back in place
        with open(tmp_file, 'wb') as ff:
            writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE, escapechar = '\'')
            writer.writerows(result)
        
        # print the progress
        percentg = int(math.floor(count / float(num_of_files) * 100))
        if percentg % 10 == 0:
                print "Progress on thread {0}".format(thread_id)
                helpers.update_progress(percentg)
    out_q.put(1)

def add_position(files_lst, numprocs):
    #files_lst = []
    #for root, dirnames, filenames in os.walk(working_dir):
    #   for filename in filenames:
    #       files_lst.append(os.path.join(root,filename))
    
    # parallelisation starts here
    #numprocs = 10
    out_q = Queue()
    chunksize = int(math.ceil(float(len(files_lst)) / float(numprocs)))
    procs = []
    for i in range(numprocs):
        sublist = files_lst[i*chunksize:(i+1)*chunksize]
        p = Process(target = worker, args = (sublist, out_q, i))
        procs.append(p)
        p.start()

    for i  in range(numprocs):
        out_q.get()

if __name__ == '__main__':
    pass            
