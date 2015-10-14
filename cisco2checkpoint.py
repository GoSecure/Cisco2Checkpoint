#!/usr/bin/python2
# -*- coding: utf-8 -*-

'''
This script let someone import a Cisco config file and export it in a dbedit compatible checkpoint config file
@author: Martin Dubé
@organization: GoSecure
@license: Modified BSD License
@contact: mdube@gosecure.ca
Copyright (c) 2015, GoSecure
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

# Python version validation
import sys
if sys.version_info > (2,7,10):
    print('Python version 2.7 is needed for this script')
    exit(1);

sys.path.insert(0, 'lib')
del sys

# Project imports
from cisco2checkpoint_lib import Cisco2Checkpoint,Cisco2CheckpointManager
from config import *

# System imports
import argparse
import os

# Get args
description = '''GoSecure cisco2checkpoint migration tool.\n

Known limitations:
 - DBEdit cannot import output if it was generated from a Windows Machine
 - The script cannot add new firewall rules. It can only update currently existing one.
 - The script support only tcp, udp and icmp protocols (Doesn't support rpc)
 - The script support only Accept and Drop actions
 - The script support only None and Log tracking
 - The script does not support "Install On" field yet.
 - The script does not support "VPN" field yet.
 - The script create only static NAT rules (not dynamic ones)
'''
epilog = '''
Examples:
Print a summary of what is parsed
  C:\python27\python27.exe cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --summary

Search some objects
  C:\python27\python27.exe cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --search 'obj-172.16.66.0' --format text
  C:\python27\python27.exe cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --search 'obj-172.16.66.0' --format text --filter CiscoHost

Export in a human readable form
  C:\python27\python27.exe cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --export --format text
  
Export for dbedit
  C:\python27\python27.exe cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --export --format dbedit --policy Standard --installOn fw01 --installOn fw02
'''
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, \
									description=description, epilog=epilog)
parser.add_argument('-v','--version', action='version', version='%(prog)s '+C2C_VERSION)
parser.add_argument('--debug', action='store_true', dest='debug', default=False, \
                    help='Run the tool in debug mode')

actGrp = parser.add_argument_group("Action", "Select one of these action")
actGrp.add_argument('--summary', '-u', action='store_true', dest='summary', default=False, \
              help='Print a summary of what is parsed and what would be migrated.')
actGrp.add_argument('--search', '-s',  action='store', dest='search', default='',\
              type=str, metavar='TEXT', help='Search for a specific object.')
actGrp.add_argument('--export', '-e', action='store_true', dest='export', default=False, \
              help='Export configuration. Use --format to determine format.')
actGrp.add_argument('--verify', action='store_true', dest='verify', default=False, \
              help='Export configuration like --export but in text format and in a verifyable format.')

optGrp = parser.add_argument_group("Option", "Use any depending on chosen action")
optGrp.add_argument('--ciscoFile', '-c', action='store', dest='ciscoFile', default='', \
              type=str, metavar='FILE', help='[Mandatory] Cisco config file to parse.')
optGrp.add_argument('--ciscoDir', '-d', action='store', dest='ciscoDir', default='', \
              type=str, metavar='DIR', help='config directory to parse. Will read only *.Config files')
optGrp.add_argument('--policy', '-p', action='store', dest='policy', default=DEFAULT_POLICY, \
              type=str, help='The policy name. Relevant with --export only. Default: %s' % DEFAULT_POLICY)
optGrp.add_argument('--installOn', '-i', action='store', dest='installOn', default=DEFAULT_INSTALLON, \
              type=str, metavar='FWs', help='Specify the checkpoint object to install rules on. ')
optGrp.add_argument('--natInstallOn', action='store', dest='natInstallOn', default=DEFAULT_NAT_INSTALLON, \
              type=str, metavar='FW', help='The firewall to use for all hide and static NAT rules.')
optGrp.add_argument('--format', '-f', action='store', dest='format', default=DEFAULT_FORMAT, \
              type=str, help='Specify the format. Valid values: dbedit, text. Default: %s' % DEFAULT_FORMAT)
optGrp.add_argument('--cpPortsFile', action='store', dest='cpPortsFile', default=DEFAULT_CP_PORT_FILE, \
              type=str, metavar='FILE', help='Checkpoint xml port file to parse. Default: %s' % DEFAULT_CP_PORT_FILE)
optGrp.add_argument('--cpNetObjFile', action='store', dest='cpNetObjFile', default=DEFAULT_CP_NETOBJ_FILE, \
              type=str, metavar='FILE', help='Checkpoint xml network objects file to parse. Default: %s' % DEFAULT_CP_NETOBJ_FILE)			  
optGrp.add_argument('--output', '-o', action='store', dest='output', default=DEFAULT_OUTPUT_FILE, \
              type=str, metavar='FILE', help='Output file. Default: %s' % DEFAULT_OUTPUT_FILE)
optGrp.add_argument('--startIndex', action='store', dest='startIndex', default=FW_RULE_INDEX, \
              type=int, metavar='INDEX', help='Index to start importing firewall rules. Default: %i' % FW_RULE_INDEX)
optGrp.add_argument('--filter', action='append', dest='filter', default=None, \
              type=str, metavar='CLASS', help='Filter a class name, e.g. CiscoHost, CiscoPort, CiscoFwRule. Can use option several times.')
optGrp.add_argument('--stdout', action='store_true', dest='stdout', default=False, \
              help='Print output to stdout.')
optGrp.add_argument('--disableRules', action='store_true', dest='disableRules', default=False, \
              help='Disable all firewall rules.')
optGrp.add_argument('--flattenInlineNetGroups', action='store_true', dest='flattenInlineNetGroups', default=False, \
              help='Flatten groups with prefix DM_INLINE_NETWORK_ so members are added to firewall rules instead of the group.')
optGrp.add_argument('--flattenInlineSvcGroups', action='store_true', dest='flattenInlineSvcGroups', default=False, \
              help='Flatten groups with prefix DM_INLINE_SERVICE_ so members are added to firewall rules instead of the group.')
args = parser.parse_args()

# Step 1: Instantiate c2c
if not os.path.isfile(str(args.cpPortsFile)):
	print('Cannot find checkpoint port file: "%s"' % args.cpPortsFile)
	exit(1)
elif not ((args.ciscoFile and os.path.isfile(str(args.ciscoFile))) \
  or (args.ciscoDir and os.path.isdir(args.ciscoDir))): # if dir was specified
	print('You must specify either a file or a dir (see --ciscoFile and --ciscoDir)')	
	exit(1)

if args.ciscoFile != '':
	c2c = Cisco2Checkpoint()
	c2c.setDebug(args.debug)
	c2c.setPolicy(args.policy)
	c2c.setInstallOn(args.installOn)
	c2c.setNatInstallOn(args.natInstallOn)
	c2c.setDisableRules(args.disableRules)
	c2c.setFWRuleIndex(args.startIndex)
	c2c.setFlattenInlineNetGroups(args.flattenInlineNetGroups)
	c2c.setFlattenInlineSvcGroups(args.flattenInlineSvcGroups)
	c2c.importConfig(args.cpPortsFile,args.cpNetObjFile,args.ciscoFile)
elif args.ciscoDir != '':
	c2c = Cisco2CheckpointManager()
	c2c.setDebug(args.debug)
	c2c.setPolicy(args.policy)
	c2c.setInstallOn(args.installOn)
	c2c.setNatInstallOn(args.natInstallOn)
	c2c.setDisableRules(args.disableRules)
	c2c.setFWRuleIndex(args.startIndex)
	c2c.setFlattenInlineNetGroups(args.flattenInlineNetGroups)
	c2c.setFlattenInlineSvcGroups(args.flattenInlineSvcGroups)
	c2c.importConfig(args.cpPortsFile,args.cpNetObjFile,args.ciscoDir)

# Step 2: Process user request
#try:
if args.summary:
	print(MSG_PREFIX+'Generate Summary')
	print(c2c.getSummary())
elif args.search != '':
	if args.filter == None:
		print(MSG_PREFIX+"Searching for an object. No filter")
		obj_list = c2c.findObjByName(args.search)
		if len(obj_list) > 0:
			print(''.join([obj.toString() for obj in obj_list]))
		else:
			print(MSG_PREFIX+'No object found')
	else:
		print(MSG_PREFIX+"Searching for an object with filter(s): %s" % ','.join(args.filter))
		obj_list = c2c.findObjByNameType(args.search,args.filter)
		if len(obj_list) > 0:
			print(''.join([obj.toString() for obj in obj_list]))
		else:
			print(MSG_PREFIX+'No object found')
elif args.export:
	result = ''
	if args.filter == None:
		if args.format == 'text':
			print(MSG_PREFIX+'Exporting to text format')
			result = c2c.getAllObjs()
		elif args.format == 'dbedit':
			print(MSG_PREFIX+'Exporting to dbedit format')
			result = c2c.toDBEdit()
		else:
			print(WARN_PREFIX+'Invalid format')
	else:
		if args.format == 'text':
			print(MSG_PREFIX+'Exporting to text format')
			obj_list = c2c.findObjByType(args.filter)
			if len(obj_list) > 0:
				result += ''.join([obj.toString() for obj in obj_list])
			else:
				print(MSG_PREFIX+'No object found')
		elif args.format == 'dbedit':
			print(MSG_PREFIX+'Operation not supported yet')
		else:
			print(WARN_PREFIX+'Invalid format')
	
	# Print summary
	print(c2c.getSummary())

	# Output
	if args.stdout:
		print(result)
	else:
		fd = os.open(args.output, os.O_RDWR|os.O_CREAT|os.O_TRUNC)
		os.write(fd,result)
		os.close(fd)
elif args.verify:
	result = ''
	args.format = 'text'
	
	if args.filter == None:
		print(MSG_PREFIX+'Exporting to verify format')
		result = c2c.getAllObjs(True)
	else:
		print(MSG_PREFIX+'Exporting to verify format')
		obj_list = c2c.findObjByType(args.filter)
		if len(obj_list) > 0:
			result += ''.join([obj.toString('', True) for obj in obj_list])
		else:
			print(MSG_PREFIX+'No object found')

	# Print summary
	print(c2c.getSummary())

	# Output
	if args.stdout:
		print(result)
	else:
		fd = os.open(args.output, os.O_RDWR|os.O_CREAT|os.O_TRUNC)
		os.write(fd,result)
		os.close(fd)
else:
	parser.print_help()
