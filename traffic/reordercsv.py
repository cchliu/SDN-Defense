import csv
import os
import math
from subprocess import call
from multiprocessing import Process, Queue
import helpers
import settings


def worker(sublist, out_q, thread_id):
	num_of_files = len(sublist)
	count = 0

	for tmp_file in sublist:
		result = {}
		count += 1 
		with open(tmp_file, 'rb') as ff:
			reader = csv.reader(ff, delimiter='\t', quoting = csv.QUOTE_NONE)
			for line in reader:
				try:
					time_epoch = float(line[2])
				except ValueError:
					print tmp_file
					print line
					
				if not time_epoch in result:
					result[time_epoch] = [line]
				else:
					result[time_epoch].append(line)
		# sort based on time_epoch
		keysList = result.keys()
		keysList = sorted(keysList)
		
		# write reordered entries back in place
		with open(tmp_file, 'wb') as ff:
			writer = csv.writer(ff, delimiter = '\t', quoting = csv.QUOTE_NONE, escapechar = '\'')
			for key in keysList:
				writer.writerows(result[key])
		
                # print the progress
                percentg = int(math.floor(count / float(num_of_files) * 100))
                if percentg % 10 == 0:
                        print "Progress on thread {0}".format(thread_id)
                        helpers.update_progress(percentg)
        out_q.put(1)

def reordercsv(files_lst, numprocs):
	#files_lst = []
	#for root, dirnames, filenames in os.walk(working_dir):
	#	for filename in filenames:
	#		files_lst.append(os.path.join(root,filename))
	
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
	main()			
