"""
    For each alert, add micro_flow_id, direction, pos_in_flow
    & micro_flow_size ==> the whole matching packet attributes
    v2: for each alert, add the whole matching packet attributes
"""
import os
import csv
import hashlib
import math
from multiprocessing import Queue, Process

def buildmap(hash_file):
    mapping = {}
    tmp_proto, tmp_src_port, tmp_dst_port = 0, 0, 0
    with open(hash_file, 'rb') as ff:
        reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
        for line in reader:
            frame_number, frame_time, frame_time_epoch, frame_lenth, frame_proto, src_ip, dst_ip, src_udp_port, dst_udp_port, src_tcp_port, dst_tcp_port = line[:11]
            if 'udp' in frame_proto:
                tmp_proto = 'udp'
                tmp_src_port = src_udp_port
                tmp_dst_port = dst_udp_port
            elif 'tcp' in frame_proto:
                tmp_proto = 'tcp'
                tmp_src_port = src_tcp_port
                tmp_dst_port = dst_tcp_port
            else:
                #TODO: other than udp/tcp, what will be other transport protocol
                continue
            frame_time_epoch = float(frame_time_epoch)
            tmp_string = ' '.join([tmp_proto, src_ip, tmp_src_port, dst_ip, tmp_dst_port, '{0:.6f}'.format(frame_time_epoch)])
            if not tmp_string in mapping:
                mapping[tmp_string] = line
    return mapping

def worker(i, sublist, subdict, out_q):
    result = []
    for tmp_file in sublist:
        mapping = buildmap(tmp_file)
        for line in subdict[tmp_file]:
            proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
            # shake off corner cases
            try:
                time_epoch = float(time_epoch)
            except:
                tmp_row = line + [-1, -100, -100, -100]
                result.append(tmp_row)
                print line
                continue

            if proto != 'tcp' and proto != 'udp':
                tmp_row = line + [-1, -100, -100, -100]
                result.append(tmp_row)
                print line
                continue

            tmp_string = ' '.join([proto, src_ip, src_port, dst_ip, dst_port, '{0:.6f}'.format(time_epoch)])
            if tmp_string in mapping:
                #tmp_row = line + mapping[tmp_string][-4:]
                tmp_row = line + mapping[tmp_string]
                result.append(tmp_row)
            else:
                print "KeyError"
                print tmp_string
                print tmp_file
    out_q.put(result)

def processing(infile, outfile, splitted_csv_dir, numprocs, HASH_LENTH, HASH_DIR_LAYERS):
    filesToopen = {}
    with open(infile, 'rb') as ff:
        reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
        for line in reader:
            proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
            tmp_string = proto + ' ' + src_ip + ' ' + src_port + ' ' + dst_ip + ' ' + dst_port
    
            hash_object = hashlib.md5(tmp_string)
            hash_letters = hash_object.hexdigest()[-1*HASH_LENTH:]
            output_subdir = os.path.join(splitted_csv_dir, '/'.join(hash_letters[:HASH_DIR_LAYERS]))
            output_path_csv = os.path.join(output_subdir, hash_letters[HASH_DIR_LAYERS:])

            #print line
            #print output_path_csv

            if not output_path_csv in filesToopen:
                filesToopen[output_path_csv] = [line]
            else:
                filesToopen[output_path_csv].append(line)

    # parallellisation starts here
    files_lst = filesToopen.keys()
    out_q = Queue()
    chunksize = int(math.ceil(float(len(files_lst)) / float(numprocs)))
    procs = []
    for i in range(numprocs):
        sublist = files_lst[i*chunksize:(i+1)*chunksize]
        subdict = {}
        for tmp_file in sublist:
            subdict[tmp_file] = filesToopen[tmp_file]
        p = Process(target = worker, args = (i, sublist, subdict, out_q, ))
        procs.append(p)
        p.start()

    result = []
    for i in range(numprocs):
        result += out_q.get()

    with open(outfile, 'wb') as ff:
        writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE, escapechar = '\'')
        writer.writerows(result)

def add_alerts(files_lst, splitted_csv_dir, numprocs, HASH_LENTH, HASH_DIR_LAYERS):
        #if indir != None:
        #   files_lst = [os.path.join(indir, f) for f in os.listdir(indir) if ".csv" in f and 'added' not in f]
        #if infile != None:
        #   files_lst = [infile]

    for tmp_file in files_lst:
        processing(tmp_file, tmp_file, splitted_csv_dir, numprocs, HASH_LENTH, HASH_DIR_LAYERS)

if __name__ == "__main__":
    pass        
