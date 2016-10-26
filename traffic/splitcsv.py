"""
	splitcap: split pcaps into small 5-tuple based pcap files
	and split csvs into small 5-tuple based csv files
	5-tuple: proto, src_ip, src_port, dst_ip, dst_port
"""
import os
import glob
import csv
import math
import hashlib
import shutil
from subprocess import call
from multiprocessing import Process, Queue
import helpers
import settings

def preprocess_dirs(working_dir, HASH_DIR_LAYERS):
	# remove every sub-directories/files under working-dir
	#subdirs = glob.glob('{0}/*'.format(working_dir))
	subdirs = [os.path.join(working_dir, k) for k in os.listdir(working_dir) if os.path.isdir(os.path.join(working_dir, k))] 
	for subdir in subdirs:
		shutil.rmtree(subdir)
	
	# remove every files under working-dir
	subfiles = [os.path.join(working_dir, k) for k in os.listdir(working_dir) if os.path.isfile(os.path.join(working_dir, k))]
	for tmp_file in subfiles:
		os.remove(tmp_file)
	# build the recursive directories
	helpers.create_recursive_dirs(HASH_DIR_LAYERS, working_dir)

def add_results(tmp_string, line, splitted_csv_dir, result_csv, HASH_LENTH, HASH_DIR_LAYERS):
	hash_object = hashlib.md5(tmp_string)
	hash_letters = hash_object.hexdigest()[-1*HASH_LENTH:]
	output_subdir = os.path.join(splitted_csv_dir, '/'.join(hash_letters[:HASH_DIR_LAYERS]))
	output_path_csv = os.path.join(output_subdir, hash_letters[HASH_DIR_LAYERS:])
	
	if not output_path_csv in result_csv:
		result_csv[output_path_csv] = [line]
	else:
		result_csv[output_path_csv].append(line)

def worker(sublist, splitted_csv_dir, HASH_LENTH, HASH_DIR_LAYERS, out_q, thread_id, write_lock):
	num_of_files = len(sublist)

	tmp_proto, tmp_src_port, tmp_dst_port = 0, 0, 0
	count = 0
	for tmp_file in sublist:
		count += 1
		# key: output_file, value: []
		result_csv = {}

		
		with open(tmp_file, 'rb') as ff:
			reader = csv.reader(ff, delimiter = '\t', quoting = csv.QUOTE_NONE)
			for line in reader:
				# find the 5-tuple
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
					#TODO: other than udp/tcp, what will be other transport protocol?
					#print frame_proto
					continue
				
				# write line to both initiating and responding direction
				""" can't write to both, special case: initiating and responding md5 substring is the same"""
				# calculate md5 hash
				tmp_string = tmp_proto + ' ' + src_ip + ' ' + tmp_src_port + ' ' + dst_ip + ' ' + tmp_dst_port
				add_results(tmp_string, line, splitted_csv_dir, result_csv, HASH_LENTH, HASH_DIR_LAYERS) 
				# write to the other direction
				#tmp_string = tmp_proto + ' ' + dst_ip + ' ' + tmp_dst_port + ' ' + src_ip + ' ' + tmp_src_port
				#add_results(tmp_string, line, splitted_csv_dir, result_csv, HASH_LENTH, HASH_DIR_LAYERS)
				
		# write	results to splitted csv files
		write_lock.get()
		for outfile in result_csv:
			with open(outfile, 'ab') as ff:
				# only one process can write the same file at a time
				writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE, escapechar = '\'')
				writer.writerows(result_csv[outfile])
		write_lock.put(1)
		
		# print the progress
		percentg = int(math.floor(count / float(num_of_files) * 100))
		if percentg % 10 == 0:
			print "Progress on thread {0}".format(thread_id)
			helpers.update_progress(percentg)
	out_q.put(1)

def splitcsv(files_lst, splitted_csv_dir, HASH_LENTH, HASH_DIR_LAYERS, numproc):
	# preprocessing splitted_csv_dir & splitted_pcap_dir
	preprocess_dirs(splitted_csv_dir, HASH_DIR_LAYERS)	

	# process file one-by-one 
	#files_lst = glob.glob('{0}/*.csv'.format(db_csv_dir))
	#files_lst = sorted(files_lst)

	# parallelization starts here
	#numproc = 20
	out_q = Queue()
	# only one process can write at a time
	write_lock = Queue()
	write_lock.put(1)
	chunksize = int(math.ceil(len(files_lst) / float(numproc)))
	procs = []
	for i in range(numproc):
		sublist = files_lst[i*chunksize:(i+1)*chunksize]
		p = Process(target = worker, args = (sublist, splitted_csv_dir, HASH_LENTH, HASH_DIR_LAYERS, out_q, i, write_lock))
		procs.append(p)
		p.start()

	for i in range(numproc):
		out_q.get()


if __name__ == "__main__":
	pass	
