""" 
	Define all global variables
"""
import os

def init():
	### fields_convertedtocsv file
	global fields_convertedtocsv_file
	fields_convertedtocsv_file = 'fields_convertedtocsv.txt'

	### PCAP file format
	global MAX_PKT_SIZE, GLOBAL_HEADER, PKT_HEADER
	MAX_PKT_SIZE = 65535
	GLOBAL_HEADER = 24
	PKT_HEADER = 16

	### hash parameters
	global HASH_LENTH, HASH_DIR_LAYERS
	HASH_DIR_LAYERS = 1 
	HASH_LENTH = 3
	

