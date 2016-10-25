import subprocess
import re

def run_snort(configFile, pcapFile):
    command = []
    logFile = 'tmp.txt'
    command = ["sudo", "snort", "-c", "{0}".format(configFile), "-r", "{0}".format(pcapFile)]
    with open(logFile, 'wb') as ff:
        p = subprocess.Popen(command, stdout=ff, stderr=ff)
    p.wait()

    ff = open(logFile, 'r')
    pattern_1 = re.compile("Run time for packet processing was ([0-9.]+) seconds")
    pattern_2 = re.compile("Snort processed ([0-9]+) packets")
    time = 0
    packet = 0
    for line in ff:
        times = re.findall(pattern_1, line)
        if len(times):
            time = times[0]
        packets = re.findall(pattern_2, line)
        if len(packets):
            packet = packets[0]
    return [pcapFile, time, packet]      
