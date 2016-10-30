import csv
import os
import glob
import numpy as np
import matplotlib
import matplotlib.pyplot as plt

def plot(nums, xtitle, ytitle, outfile, FLAG=False):
    xscales = [i for i in range(1,10)] + [10**k for k in np.arange(1,3,0.1)]
    lenth = len(nums)
    cdf = []
    for i in xscales:
        tmp_count = sum([1 for k in nums if k <= i])
        percentg = float(tmp_count) / float(lenth)
        cdf.append(percentg)

    plt.figure(1)
    plt.subplot(111)
    axes = plt.gca()
    plt.semilogx(xscales, cdf, color = 'b', linewidth = 2)
    if FLAG:
        plt.ylim([0.9, 1.0])
    plt.xlabel(xtitle, fontsize=17, fontweight='bold')
    plt.ylabel(ytitle, fontsize=17, fontweight='bold')
    matplotlib.rc('text', usetex=True)
    matplotlib.rcParams['text.latex.preamble'] = [r'\boldmath']
    ftsize = 20
    for tick in axes.xaxis.get_major_ticks():
        tick.label1.set_fontsize(ftsize)
        tick.label1.set_fontweight('bold')
    for tick in axes.yaxis.get_major_ticks():
        tick.label1.set_fontsize(ftsize)
        tick.label1.set_fontweight('bold')
    axes.tick_params('both', length=10, width=1, which='major')
    axes.tick_params('both', length=5, width=1, which='minor')
    #plt.title(title)
    #plt.ticklabel_format(style='sci', axis='y', scilimits=(0,0))
    axes.yaxis.get_offset_text().set_fontsize(20)
    plt.grid(True)
    plt.savefig(outfile)
    plt.close()
 
def find_earliest_pos_in_flow(result):
    mapping = {}
    for line in result:
        proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
        micro_flow_id, tmp_direction, pkt_in_position, micro_flow_lenth = line[-4:] 
        # pos_in_flow starts from 0
        pkt_in_position = int(pkt_in_position)
        if pkt_in_position >= 0:
            tmp_string = ' '.join([proto, src_ip, src_port, dst_ip, dst_port, micro_flow_id, tmp_direction, sid])
        ### debug
        #if pkt_in_position + 1 <= 2:
        #   print line
        if not tmp_string in mapping:
            mapping[tmp_string] = [pkt_in_position+1]
        else:
            mapping[tmp_string].append(pkt_in_position+1)
 
    # earlist pos_in_flow for each (flow, sid) pair 
    output = [sorted(mapping[k])[0] for k in mapping]
    return output

def stats_3(files_lst, postfix):
    result = []
    for tmpfile in files_lst:
        with open(tmpfile, 'rb') as ff:
            reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
            for line in reader:
                result.append(line)

    # extract out tcp/udp alerts
    result_all = [line for line in result if line[0] == 'tcp' or line[0] == 'udp']
    nums = find_earliest_pos_in_flow(result_all)
    xlabel = r'\textbf{K parameter}'
    ylabel = r'\textbf{Performance of detection}'
    outfile = 'detectability_K_all_{0}.png'.format(postfix)
    plot(nums, xlabel, ylabel, outfile) 
    #cdf_plot_semilogx(nums, xscales, **kwargs)
   
    # extract out tcp alerts
    result_tcp = [line for line in result if line[0] == 'tcp']
    nums = find_earliest_pos_in_flow(result_tcp)
    outfile = 'detectability_K_tcp_{0}.png'.format(postfix)
    plot(nums, xlabel, ylabel, outfile)

    # extract out tcp alerts
    result_udp = [line for line in result if line[0] == 'udp']
    nums = find_earliest_pos_in_flow(result_udp)
    outfile = 'detectability_K_udp_{0}.png'.format(postfix)
    plot(nums, xlabel, ylabel, outfile, True)
 
def main():
    #log_dir = '/home/cchliu/data/log/wifi/0530'
    log_dir = '/home/chang/tmp/alerts'
    files_lst = glob.glob('{0}/*.csv'.format(log_dir))
    stats_3(files_lst, '0530')
        
if __name__ == "__main__":
    main()
