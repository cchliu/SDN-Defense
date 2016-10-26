import re
import datetime
from time import mktime
import settings

def getPriority(line):
	pattern = r'Priority: (\d)'
	match = re.search(pattern, line)
	if match != None:
		priority = int(match.groups()[0])
		return priority
	return None


def getClassification(line):
	pattern = r'\[Classification\: ([^]]+)\]'
	match = re.search(pattern, line)
	if match != None:
		classification = match.groups()[0]
		return classification
	return None

				
def getSID(line):
	pattern = r'\d+:(\d+):\d+'
	match = re.search(pattern, line)
	if match != None:
		sid = int(match.groups()[0])
		return sid
	return None

 
def getMsg(line):
	pattern = r'\d+:\d+:\d+'
	match = re.search(pattern, line)
	if match != None:
		msg = line[match.end()+1:-4]
		msg = msg.rstrip(' ').lstrip(' ')
		return msg
	return None
			

def getEpochTime(line):
	pattern = r'(\d+)/(\d+)-([-,\d]+):([-,\d]+):([-,\d]+)\.(\d+)'
	match = re.search(pattern, line)
	if match != None:
		month, day, hh, mm, ss, micross = [int(k) for k in match.groups()]
		# only work for year 1969
		if hh<0 or mm<0 or ss<0:
			basetime = datetime.datetime(1970, 1, 1, 0, 0, 0)
			basetime = mktime(basetime.timetuple())
			minustime = hh*-1*3600 + mm*-1*60 + ss*-1
			epoch = minustime * -1 + basetime + micross* 1e-6
		# normal years
		else:
			date_time = datetime.datetime(int(settings.traffic_year), month, day, hh, mm, ss)
			epoch = mktime(date_time.timetuple()) + micross * 1e-6
		epoch = epoch + settings.tz_offset * 3600	
		return epoch
	return Nonw
	

def getIpPort(line):
	### IPV4
	pattern = r'\d+\.\d+\.\d+\.\d+:\d+'
	match = re.findall(pattern, line)
	if match != None and len(match) == 2:
		src_ip = match[0]
		ip1, ip2, ip3, ip4, src_port = [k for k in re.findall(r'\d+', src_ip)]
		src_ip = '.'.join([ip1, ip2, ip3, ip4])
		#src_ip_int = ip1 * 256*256*256 + ip2 * 256*256 + ip3 * 256 + ip4
		
		dst_ip = match[1]
		ip1, ip2, ip3, ip4, dst_port = [k for k in re.findall(r'\d+', dst_ip)]
		dst_ip = '.'.join([ip1, ip2, ip3, ip4])
		#dst_ip_int = ip1 * 256*256*256 + ip2 * 256*256 + ip3 * 256 + ip4
		#return (src_ip_int, src_port, dst_ip_int, dst_port)
		return (src_ip, src_port, dst_ip, dst_port) 
	### TODO: IPV6
	return (None, None, None, None)


def getProto(line):
	proto = line.split(' ')[0]
	proto = proto.lower()
	return proto		
	
