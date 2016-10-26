"""
	Extract packet fields from pcap and store it in csv
"""
import os
import glob
import csv
import math
from subprocess import call
from multiprocessing import Process, Queue
import settings
import helpers

def worker(sublist, cmd, pcapTocsv_dir, out_q, thread_id):	
	count = 0
	lenth = len(sublist)
	for tmp_file in sublist:
		count += 1
		my_cmd = cmd
		my_cmd[2] = tmp_file
	
		out_fname = os.path.join(pcapTocsv_dir, os.path.basename(tmp_file)+'.csv')	
		with open(out_fname, 'wb') as ff:
			call(my_cmd, stdout=ff)		
		
		percentg = int(math.floor(count / float(lenth) * 100))
		if percentg % 10 == 0:
			print "Progress on thread {0}".format(thread_id)
			helpers.update_progress(percentg)			 
	out_q.put(1)
		
def run_pcapTocsv(files_lst, pcapTocsv_dir, numproc):
	# no need to remove old files in pcapTocsv_dir because of 'wb' mode
	#files_lst = glob.glob('{0}/*'.format(pcap_dir))
	#files_lst = sorted(files_lst)

	tmp_file = '' 
	my_cmd = ['tshark', '-r', tmp_file, '-T', 'fields', '-E', 'separator=/t']
	with open(settings.fields_convertedtocsv_file, 'rb') as ff:
		reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
		for line in reader:
			# remove the comment lines
			if len(line) > 0 and line[0][0] != '#':
				my_cmd.append('-e')
				my_cmd.append(line[0])
			
	# parallelization starts here
	#numproc = 20
	out_q = Queue()
	chunksize = int(math.ceil(len(files_lst) / float(numproc)))
	procs = []
	for i in range(numproc):
		sublist = files_lst[i*chunksize:(i+1)*chunksize]
		p = Process(target = worker, args = (sublist, my_cmd, pcapTocsv_dir, out_q, i))
		procs.append(p)
		p.start()

	for i in range(numproc):
		out_q.get()
	
if __name__ == "__main__":
	pass	
