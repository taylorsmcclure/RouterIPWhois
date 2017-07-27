#!/usr/bin/env python

import sys
import telnetlib
from optparse import OptionParser
from getpass import getpass
from ipwhois import IPWhois

usage = "usage: grab_conns.py [options] arg1 arg2"
parser = OptionParser(usage=usage)
parser.add_option("-u", "--user", dest="user",
                  help="user to log into the router")
parser.add_option("-r", "--router-ip", dest="router",
                  help="The IP of your router e.g. 192.168.0.1")

(options, args) = parser.parse_args()

if not options.user:
    parser.error('Username has to be given')
if not options.router:
    parser.error('Router IP has to be given')

password = getpass()
if not password:
    print("Password has to be given")
    sys.exit(1)

cmd = "netstat-nat -no"
tn = telnetlib.Telnet()

tn.open(options.router, 23, 30)

tn.read_until("RT-AC66U login: ", 5)
tn.write(options.user + "\n")

tn.read_until("Password: ")
tn.write(password + "\n")
tn.read_until("RT-AC66U login: ", 5)

tn.read_until("admin@RT-AC66U:/tmp/home/root# ", 5)
tn.write(cmd + "\n")

output = tn.read_until("admin@RT-AC66U:/tmp/home/root# ")
output = output.split()
output = output[2:-1]
output = [output[x:x+4] for x in range(0, len(output), 4)]

ips = []

for entry in output:
    entry = entry[2].split(':')
    if entry[0] != '8.8.8.8' or '8.8.4.4':
        ips.append(entry[0])

for ip in ips:
    obj = IPWhois(ip)
    result = obj.lookup_whois(inc_nir=True)
    if result["asn_cidr"] != '199.5.26.0/24':
        if result["asn_country_code"] != "US":
            results = []
            results.append(result["asn_country_code"])
            results.append(result["query"])
            results.append(result["nets"][0]["description"])
            results.append(result["nets"][0]["address"])
            results.append(result["nets"][0]["name"])
            print(results)
    # print(result)

tn.close()
