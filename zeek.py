import nmap
from datetime import datetime
from fileinput import close
import json
import sys

def main():
    hashtagremoval()
    filtering_ip()
    privip_filtering()
    activeIpsList = Activity_filter()
    Scanning(activeIpsList)

#removing hashtags from conn.log, because this caused problems with indexing in array
def hashtagremoval():
    filepath = "/opt/zeek/logs/2022-06-06/conn.log"
    a_file = open(filepath, "r")
    lines = a_file.readlines()
    a_file.close()

    for x in range(0, 8):
        del lines[0]

    new_file = open(filepath, "w+")
    for line in lines:
        new_file.write(line)
        new_file.close()

#filtering/selecting all ip addresses from log file.
def filtering_ip():
    filepath = "/opt/zeek/logs/2022-06-06/conn.log"
    ip_filterd = {"127.0.0.1"}
    w = open("zeek.log", "w+")
    f = open(filepath, "r")
    for line in f:
        linestrip = line.strip().split("\t")
        try:
            ip = linestrip[2]
            ip_filterd.add(ip)
        except (IndexError) as error:
            pass

    w.write(f"{ip_filterd}")
    f.close()
    w.close()

#filtering all private ip addresses out of the log file
def privip_filtering():
    internalIp = '192.168.0.0/16'
    count = 0
    ipFile = "zeek.log"  # name of the file containing all IPs that will be used as input for this
    outputFile = "internalIps" + (datetime.now().strftime('%d+%m+%Y')) + '.json'  # output file with filtered IPs
    netmask = (int)(internalIp.split('/')[1])
    internalIp = internalIp.split('/')[0]
    splitInternalIp = internalIp.split('.')
    constantIp = netmask // 8
    netmaskRemainder = netmask % 8
    internalSection = (int)(splitInternalIp[constantIp])
    cutInternalSection = internalSection >> (8 - netmaskRemainder)
    filteredIps = []

    with open(outputFile, 'w+') as output:
        with open(ipFile, 'r') as file:
            for line in file:
                ipArray = line.split(',')
                for ip in ipArray:
                    if ':' in ip or '.' not in ip:
                        continue
                    check = True
                    strippedIp = ip.strip("'{ }")
                    splitIp = strippedIp.split('.')
                    for i in range(constantIp):
                        if splitIp[i] != splitInternalIp[i]:
                            check = False
                    if netmaskRemainder != 0:
                        ipSection = (int)(splitIp[constantIp])
                        if cutInternalSection != (ipSection >> (8 - netmaskRemainder)):
                            check = False
                    if check:
                        filteredIps.append(strippedIp)

            output.write(json.dumps(filteredIps))

#Comparing yesterday & todays IP's to get active IP's
def Activity_filter():

    # Filtering log file for active clients
    newEntries = "internalIps17+06+2022.json"
    oldEntries = "yesterdaysIps.json"

    with open(newEntries) as f1, open(oldEntries) as f2:
        newIps = json.load(f1)
        oldIps = json.load(f2)

    def filterActiveIps(ip):
        if ip in oldIps:
            return ip

    activeIps = list(filter(filterActiveIps, newIps))
    return activeIps

#scanning all active ip addresses with nmap for vunerabillities
def Scanning(activeIps):
	nm = nmap.PortScanner()
	now = datetime.now()
	current_date = now.strftime('%d-%m-%Y')
	current_time = now.strftime('%H:%M:%S')
	f = open(f'data-{current_date}.txt', 'x')
	sys.stdout = f

	try:
		for ip in activeIps:
			print("scanning")
			nm.scan(ip, '20-1024', '-sV')
			print(nm[ip].all_protocols())
			print("Datum : ", current_date)
			print("Tijd :", current_time)
			print("Host : %s (%s)" % (ip, nm[ip].hostname()))
			print("State : %s" % nm[ip].state())
			for proto in nm[ip].all_protocols():
				print("----------")
				print("Protocol : %s" % proto)
				lport = nm[ip][proto].keys()
				sorted(lport)
				for port in lport:
					print("port : %s\tstate : %s" % (port, nm[ip][proto][port]['state']))
				print("__________________________", "\n")
	except KeyError:
		pass
	f.close()
	sys.stdout = f


if __name__ == "__main__":
    main()