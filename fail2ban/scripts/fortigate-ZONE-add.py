#!/usr/bin/python

#
# fortigate-ZONE-add.py
#
# 10/03/2018   Tim B   Original
#
#
# Python Script to use the Fortigate API for Fail2ban, based on various scripts found on the Internet
# such as: https://github.com/eoprede/fortigate_api
#
# called from fail2ban/action.d/
#
# Usage: fortigate-dmz-add.py [--debug N] <IP Address>
#

# Note: change ZONE to your Network Interface Name/Zone Name
#       Change USERCODE to the usercode you setup on the Fortigate
#       Change PASSWORD to the password of the above account
#       Change VDOMNAME to the VDOM you are using
#       Change IPADDRESS to the IP Address of the Fortigate
#
import getpass
import json
from optparse import OptionParser
import pprint
import requests
import sys
import syslog

#
# Globally Defined Values
#
iDebug=0
sFGTIP="IPADDRESS"
sVDOM="VDOMNAME"
sGroup="ZONE_IP_Blacklist"
sFGTUC="USERCODE"
sFGTPW="PASSWORD"
sIPPrefix="BL_ZONE_IP_"

#
# Fortigate API Class/Defines
#
class fortigate_api:

    _secure=True

    def __init__(self, ip, un, pw, verify=False, proxies=None, disable_warnings=True):
        if disable_warnings:
            requests.packages.urllib3.disable_warnings()
        unpw = {'username':un,'secretkey':pw}
        self.verify = verify
        self.ip = ip
        self.proxies=proxies
        auth = requests.post('https://'+self.ip+'/logincheck', data=unpw, verify=self.verify, proxies=self.proxies)
        self.cookies = auth.cookies
        for cookie in self.cookies:
            if cookie.name == "ccsrftoken":
                csrftoken = cookie.value[1:-1]  # token stored as a list
                self.header = {"X-CSRFTOKEN": csrftoken}

    def __enter__(self):
        return self

    def __del__(self):
        if self._secure:
            http='https://'
        else:
            http='http://'
        try:
            requests.post(http+self.ip+'/logout', verify=self.verify, cookies=self.cookies, proxies=self.proxies)
        except AttributeError:
            print ("Looks like connection to "+self.ip+" has never been established")



    def __exit__(self, *args):
        pass

    def get(self, path, api='v2', params=None):
        if isinstance(path, list):
            path = '/'.join(path) + '/'
        if self._secure:
            http='https://'
        else:
            http='http://'
        return requests.get(http+self.ip+'/api/'+api+'/'+path, cookies=self.cookies, verify=self.verify, proxies=self.proxies, params=params)

    def put(self, path, api='v2', params=None, data=None):
        if isinstance(path, list):
            path = '/'.join(path) + '/'
        if self._secure:
            http='https://'
        else:
            http='http://'
        return requests.put(http+self.ip+'/api/'+api+'/'+path, headers=self.header,cookies=self.cookies, verify=self.verify, proxies=self.proxies, params=params, json={'json': data})

    def post(self, path, api='v2', params=None, data=None, files=None):
        if isinstance(path, list):
            path = '/'.join(path) + '/'
        if self._secure:
            http='https://'
        else:
            http='http://'
        return requests.post(http+self.ip+'/api/'+api+'/'+path, headers=self.header,cookies=self.cookies, verify=self.verify, proxies=self.proxies, params=params, json={'json': data}, files=files)

    def delete(self, path, api='v2', params=None, data=None):
        if isinstance(path, list):
            path = '/'.join(path) + '/'
        if self._secure:
            http='https://'
        else:
            http='http://'
        return requests.delete(http+self.ip+'/api/'+api+'/'+path, headers=self.header,cookies=self.cookies,verify=self.verify, proxies=self.proxies, params=params, json={'json': data})

    def show(self, path, api='v2', params=None):
        response = self.get(path, api=api, params=params)
        return response.json()

    def edit(self, path, api='v2', params=None, data=None):
        response = self.put(path, api=api, params=params, data=data)
        return response.json()

    def create(self, path, api='v2', params=None, data=None, files=None):
        response = self.post(path, api=api, params=params, data=data, files=files)
        return response.json()

    @staticmethod
    def print_data(response, verbose=False):
        if response['status']=='success':
            if verbose:
                pprint.pprint (response)
            elif response['http_method']=='GET':
                pprint.pprint (response['results'])
            else:
                print ('OK!')
        else:
            print ('Fail!')
            pprint.pprint (response)


							
							
#
# Misc Functions
#

# Debug
def debug_print ( intLevel, strMessage ):
    if intLevel <= iDebug:
	   print strMessage

#
# Main
#

# isable warnings about certificates
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# setup Syslog config
syslog.openlog(ident="fortigate_ZONE_add",logoption=syslog.LOG_PID)

# Setup the Command line Options
oParser=OptionParser()
oParser.add_option("-d", "--debug", dest="debug", type="int", action="store", default=0, help="Debug Level 1-9")
(oOptions,oArgs)=oParser.parse_args()

iDebug=oOptions.debug
if len(oArgs) != 1:
   print "No IP Address Provided"
   syslog.syslog( "No IP Address Provided")
   print "Usage: fortigate_ZONE_add.py [--debug=N] <IPAddress>"
   sys.exit(-1)

sIPAddr = oArgs[0]
debug_print(1,"sIPAddr = " + sIPAddr)
oFGT = fortigate_api(sFGTIP, sFGTUC, sFGTPW, proxies = None)
#
# Add an Address Record
sAddrRec = { "allow-routing":"disable",
"name":sIPPrefix + sIPAddr,
"start-ip":sIPAddr,
"subnet":sIPAddr + " 255.255.255.255",
"type":"ipmask",
"visibility":"enable",
"wildcard":sIPAddr + " 255.255.255.255"}

#debug_print(1,"sAddrRec = " + str(sAddrRec))
jRslt = oFGT.create(['cmdb', 'firewall', 'address'], params={'vdom':sVDOM}, data=sAddrRec)
debug_print(1,"jRslt = " + str(jRslt))
if not "success" in jRslt["status"]:
   # Error Logging
   debug_print(1,"Error Adding Address Record " + sIPPrefix + sIPAddr + ". Error = " + str(jRslt))
   syslog.syslog("Error Adding Address Record " + sIPPrefix + sIPAddr + ". Error = " + str(jRslt))
   sys.exit(-1)


# Add the Address to the Group
sAddrAdd = {"name":sIPPrefix + sIPAddr}
jRslt = oFGT.create(['cmdb','firewall','addrgrp',sGroup,'member'], data=sAddrAdd, params={'vdom':sVDOM})
debug_print(1,"jRslt = " + str(jRslt))
if iDebug >= 1:
   pprint.pprint(jRslt)

# Add code to check if create succeeded
if not "success" in jRslt["status"]:
   # Error Logging
   debug_print(1,"Error Adding Address Record " + sIPPrefix + sIPAddr + " to groiup " + sGroup + ". Error = " + str(jRslt))
   syslog.syslog("Error Adding Address Record " + sIPPrefix + sIPAddr + " to groiup " + sGroup + ". Error = " + str(jRslt))
   sys.exit(-1)

sys.exit(0)
