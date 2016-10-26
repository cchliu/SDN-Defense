"""
	For each row(pkt), add start_byte, pkt_size, pcap_filename
"""
import csv
import glob
import os
import math
from subprocess import call
from multiprocessing import Process, Queue
import settings
import helpers

def worker(sublist, pcap_dir, outdir, out_q, thread_id):
	count = 0 
	lenth = len(sublist)
	for tmp_file in sublist:
		count += 1
		curr_byte = settings.GLOBAL_HEADER
		curr_frame_number = 0
		result = []
		
		pcap_file_path = os.path.join(pcap_dir, os.path.basename(tmp_file))
		pcap_file = pcap_file_path.rstrip('.csv')
	
		# read-in content, add pcap_file, start_byte, pkt_size
		with open(tmp_file, 'rb') as ff:
			reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
			
			for line in reader:
				curr_frame_number += 1
				frame_number, frame_time, frame_time_epoch, frame_lenth = line[:4]
				
				# calculate byte offset
				start_byte = curr_byte
				frame_lenth = int(frame_lenth)
				if frame_lenth > settings.MAX_PKT_SIZE:
					frame_lenth = settings.MAX_PKT_SIZE
				data_size = settings.PKT_HEADER + frame_lenth

				tmp = [k for k in line] + [pcap_file, curr_frame_number, start_byte, data_size]
				result.append(tmp)
				# update current byte position
				curr_byte += data_size

		# store the new csv
		#outfile = os.path.join(outdir, os.path.relpath(tmp_file, indir))
		outfile = os.path.join(outdir, os.path.basename(tmp_file))
		with open(outfile, 'wb') as ff:
			writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE, escapechar = '\'')
			for line in result:
				try:
					writer.writerow(line)
				except csv.Error:
					print line
		# print the progress
		percentg = int(math.floor(count / float(lenth) * 100))
		if percentg % 10 == 0:
			print "Progress on thread {0}".format(thread_id)
			helpers.update_progress(percentg)
	out_q.put(1)

def add_startbyte(files_lst, pcap_dir, outdir, numproc):
	#files_lst = glob.glob('{0}/*.csv'.format(pcapTocsv_dir))
	#files_lst = []
	#for root, directories, filenames in os.walk(indir):
	#	for filename in filenames:
	#		files_lst.append(os.path.join(root, filename))
	#files_lst = sorted(files_lst)

	# parallelization starts here
	#numproc = 20
	out_q = Queue()
	chunksize = int(math.ceil(len(files_lst) / float(numproc)))	
	procs = []
	for i in range(numproc):
		sublist = files_lst[i*chunksize:(i+1)*chunksize]
		p = Process(target = worker, args = (sublist, pcap_dir, outdir, out_q, i,))
		procs.append(p)
		p.start()

	for i in range(numproc):
		out_q.get()

if __name__ == "__main__":
	pass	
