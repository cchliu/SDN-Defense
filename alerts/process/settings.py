""" 
    Configure parameters here
"""
import os

def init(year, timezone_offset):
    ### hash parameters
    global HASH_LENTH, HASH_DIR_LAYERS
    HASH_DIR_LAYERS = 1
    HASH_LENTH = 3

    global traffic_year, tz_offset
    traffic_year = year
    tz_offset = timezone_offset

    # snort config path
    global snort_config_path
    snort_config_path = '/etc/snort/snort.conf'
    
