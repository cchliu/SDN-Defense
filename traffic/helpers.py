"""
	Helper functions
"""
import os

def update_progress(progress):
	progress = int(progress)
	print "\r[{0}] {1}%".format('#'*(progress/10), progress)

def create_dir(indir):
        if not os.path.exists(indir):
                os.makedirs(indir)

def create_recursive_dirs(num_layers, home_dir):
	hexdigit_values = [str(k) for k in range(10)] + ['a', 'b', 'c', 'd', 'e', 'f']
	index_layer = 0
	curr_layer = [home_dir]
	while index_layer < num_layers:
		next_layer = []
		for base_dir in curr_layer:
			for k in hexdigit_values:
				dirpath = os.path.join(base_dir, k)
				if not os.path.exists(dirpath):
					os.makedirs(dirpath)
					next_layer.append(dirpath)
		curr_layer = next_layer
		index_layer += 1	
					
