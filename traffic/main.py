import os
import glob
from run_pcapTocsv import run_pcapTocsv
from add_startbyte import add_startbyte
from splitcsv import splitcsv
from reordercsv import reordercsv
from add_position import add_position
import settings

def preprocess(subfolders):
        for subfolder in subfolders:
                tmp_pcap = os.path.join(subfolder, 'pcap')
                tmp_pcapTocsv = os.path.join(subfolder, 'pcapTocsv')
                #tmp_dbcsv = os.path.join(subfolder, 'db_csv')
                tmp_splitcsv = os.path.join(subfolder, 'splitcsv')

                if not os.path.exists(tmp_pcap):
                        os.makedirs(tmp_pcap)
                if not os.path.exists(tmp_pcapTocsv):
                        os.makedirs(tmp_pcapTocsv)
                #if not os.path.exists(tmp_dbcsv):
                #       os.makedirs(tmp_dbcsv)
                if not os.path.exists(tmp_splitcsv):
                        os.makedirs(tmp_splitcsv)

def process(subfolder):
	print subfolder
	tmp_pcap = os.path.join(subfolder, 'pcap')
	tmp_pcapTocsv = os.path.join(subfolder, 'pcapTocsv')
	tmp_splitcsv = os.path.join(subfolder, 'splitcsv')

	# run_pcapTocsv
	#files_lst = glob.glob('{0}/output*'.format(tmp_pcap))
	#if len(files_lst) == 0:
	#       files_lst = glob.glob('{0}/*'.format(tmp_pcap))
	#files_lst = sorted(files_lst)
	#run_pcapTocsv(files_lst, tmp_pcapTocsv, 5)

	#files_lst = glob.glob('{0}/*'.format(tmp_pcapTocsv))
	#files_lst = sorted(files_lst)
	# add_startbyte
	#add_startbyte(files_lst, tmp_pcap, tmp_pcapTocsv, 10)
	# splitcsv
	#splitcsv(files_lst, tmp_splitcsv, settings.HASH_LENTH, settings.HASH_DIR_LAYERS, 10)
	
	
	# add_position
	files_lst = []
	for root, dirnames, filenames in os.walk(tmp_splitcsv):
		for filename in filenames:
			files_lst.append(os.path.join(root, filename))
	files_lst = sorted(files_lst)
	# reordercsv
	#reordercsv(files_lst, 10)
	add_position(files_lst, 10)

def main():
	input_base = '/home/cchliu/data/input/wifi/0530'
	settings.init()
	preprocess([input_base])	
	process(input_base)	

if __name__ == "__main__":
	main()
