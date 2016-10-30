import csv
import operator
import glob
import matplotlib
import matplotlib.pyplot as plt
from stats_1 import count_unique_flows

def plot(result, xtitle, ytitle, outfile):
    ranking = [i+1 for i in range(len(result))]
    total_flows = sum(result)
    y = result
    #y = [float(k)/float(total_flows)*100 for k in result]

    plt.figure(1)
    plt.subplot(111)
    axes = plt.gca()
    plt.semilogx(ranking, y, color='b', linewidth=2)

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

def sids_freq(result):
    sids = {}
    for line in result:
        proto, src_ip, src_port, dst_ip, dst_port, time_epoch, sid, priority, classification, msg = line[:10]
        if not sid in sids:
            sids[sid] = [line]
        else:
            sids[sid].append(line)
    
    freq = {}
    for sid in sids:
        freq[sid] = count_unique_flows(sids[sid])
    
    sorted_sids = sorted(freq.items(), key=operator.itemgetter(1), reverse=True)    
    y = [k[1] for k in sorted_sids]
    return y

def stats_2(infiles, postfix):
    result = []
    for tmp_file in infiles:
        with open(tmp_file, 'rb') as ff:
            reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
            for line in reader:
                result.append(line)
    
    # extract out tcp/udp alerts
    result_all = [line for line in result if line[0] == 'tcp' or line[0] == 'udp']
    y = sids_freq(result_all)
    ytitle = r'\textbf{Number of flows triggering the rule}'
    xtitle = r'\textbf{rank}'
    outfile = 'distr_sids_all_{0}.png'.format(postfix)
    plot(y, xtitle, ytitle, outfile) 

    # extract out tcp alerts
    result_tcp = [line for line in result if line[0] == 'tcp']
    y = sids_freq(result_tcp)
    outfile = 'distr_sids_tcp_{0}.png'.format(postfix)
    plot(y, xtitle, ytitle, outfile)

    # extract out udp alerts
    result_udp = [line for line in result if line[0] == 'udp']
    y = sids_freq(result_udp)
    outfile = 'distr_sids_udp_{0}.png'.format(postfix)
    plot(y, xtitle, ytitle, outfile)
    
def main():
    #infile = 'table_sid_frequency_0530_security_ET.csv'
    #infile = 'table_sid_frequency_0530.csv'
    
    log_dir = '/home/chang/tmp/alerts'
    files_lst = glob.glob('{0}/*.csv'.format(log_dir))
    stats_2(files_lst, '0530')

if __name__ == "__main__":
    main()
