from os import listdir
from os.path import isfile, join
import csv
from parse_alerts import getSID, getMsg, getEpochTime, getIpPort, getProto, getPriority, getClassification
from multiprocessing import Queue, Process
import math

def worker(i, sublist, out_q):  
    ### read in all alerts
    flag = -100
    result = []
    """ initialize sid, src_ip_int, src_port, dst_ip_int, dst_port, proto, priority """
    sid, proto, src_ip, src_port, dst_ip, dst_port, time_epoch, priority, classification = 0, 0, 0, 0, 0, 0, 0, 0, 0 
    for fname in sublist:
        with open(fname, 'rb') as ff:
            for row in ff:
                row = row.rstrip('\n')
                if row[0:4] == "[**]":
                    sid = getSID(row)
                    msg = getMsg(row)
                    flag = 1
                    continue
                if flag == 1:
                    classification = getClassification(row)
                    priority = getPriority(row)
                    flag = 2
                    continue
                if flag == 2:
                    time_epoch = getEpochTime(row)
                    (src_ip, src_port, dst_ip, dst_port) = getIpPort(row)
                    flag = 3
                    continue
                if flag == 3:
                    proto = getProto(row)
                    flag = -100
                    tmp_row = [proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg]
                    result.append(tmp_row)  

        # write alerts into csv format
        outfile = fname + '.csv'
        with open(outfile, 'wb') as ff:
            writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
            writer.writerows(result)
    out_q.put(1)
    
def read_alerts(files_lst, numprocs):   
    #if indir != None:
    #   files_lst = [join(indir, f) for f in listdir(indir) if isfile(join(indir, f)) and "alert" in f and '.csv' not in f]
    #if infile != None:
    #   files_lst = [infile]

    # paralellisation starts here
    #numprocs = 5
    out_q = Queue()
    chunksize = int(math.ceil(float(len(files_lst)) / float(numprocs)))
    procs = []
    for i in range(numprocs):
            sublist = files_lst[i*chunksize:(i+1)*chunksize]
            p = Process(target = worker, args = (i, sublist, out_q))
            procs.append(p)
            p.start()

    for i in range(numprocs):
        out_q.get() 

if __name__ == "__main__":
    pass
