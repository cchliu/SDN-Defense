import sys
import os
import csv
import glob
from packet_in import packet_in
from run_snort import run_snort

def main():
    filename = ["mu_03284_20140530132156", "mu_03285_20140530132244", "mu_03286_20140530132340", "mu_03287_20140530132440", "mu_03288_20140530132540"]
    pcap_csv_dir = "/home/cchliu/data/input/wifi/0530/pcapTocsv"
    pcap_csv_file = [os.path.join(pcap_csv_dir, '{0}.csv'.format(k)) for k in filename]
    pcap_dir = "/home/cchliu/data/input/wifi/0530/pcap"
    pcap_file = [os.path.join(pcap_dir, '{0}'.format(k)) for k in filename]
    
    start = filename[0].split('_')[1]
    end = filename[-1].split('_')[1]
    out_dir = 'tmp/{0}'.format(start + '_' + end)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    K_lst = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    # extract packets sent to controller at various K (least-load)
#    for K in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
#        packet_in(filename, pcap_file, pcap_csv_file, out_dir, K)
    
    # run packets against Snort
    configFile = '/etc/snort/snort.conf'
    pcapFiles = sorted(glob.glob(os.path.join(out_dir, '*')))
    result = []
    for i in range(len(pcapFiles)):
        pcapFile = pcapFiles[i]
        result.append(run_snort(configFile, pcapFile))

    filename = os.path.basename(out_dir)
    outfile = os.path.join(out_dir, filename + '.csv')
    with open(outfile, 'wb') as ff:
        writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
        writer.writerows(result) 
       
if __name__ == "__main__":
    main()      
             
