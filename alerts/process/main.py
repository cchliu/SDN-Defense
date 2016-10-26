import os
import csv

import settings
from read_alerts import read_alerts
from add_alerts import add_alerts

def buildalerts(log_dir, pcap_dir):
	files_lst = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if "alert" in f and '.csv' not in f]
	read_alerts(files_lst, 10)

	files_lst = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if "alert" in f and '.csv' in f]
	splitted_csv_dir = os.path.join(pcap_dir, 'splitcsv')
	#print splitted_csv_dir
	add_alerts(files_lst, splitted_csv_dir, 10, settings.HASH_LENTH, settings.HASH_DIR_LAYERS)


def main():
	log_dir = '/home/cchliu/data/log/wifi/0530'
	#log_dir = '/home/cchliu/data/log_nopolicy_ET/wifi/0530'
	pcap_dir = '/home/cchliu/data/input/wifi/0530'
	settings.init(2014, 0)	
	buildalerts(log_dir, pcap_dir)

if __name__ == "__main__":
	main()
	


