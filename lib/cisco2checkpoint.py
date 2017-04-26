#!/usr/bin/python2
# -*- coding: utf-8 -*-

'''
@author: Martin Dubé
@organization: GoSecure
@contact: mdube@gosecure.ca
@license: GPLv3
Copyright (c) 2016, GoSecure

This file is part of cisco2checkpoint project.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from ciscoconfparse_patch import CiscoConfParse
from config import *
import xml.etree.ElementTree as et
import copy
import socket
import os
import re

ACL_RULE_INDEX = DEFAULT_ACL_RULE_INDEX

def isarray(var):
    return isinstance(var, (list, tuple))
    
def isipaddress(var):
    try:
        socket.inet_aton(var)
        return True
    except socket.error:
        return False

def mask2cidr(mask):
    return sum([bin(int(x)).count('1') for x in mask.split('.')])       

def flatten_array(l):
    res = []
    iters_stack = [iter(l)]
    while iters_stack:
        for e in iters_stack[-1]:
            if isinstance(e, (tuple,list)):
                iters_stack.append(iter(e))
                break
            res.append(e)
        else:
            iters_stack.pop()
    return res 

def print_msg(msg):
    print(MSG_PREFIX+msg)

def print_debug(msg):
    if C2C_DEBUG:
        print(WARN_PREFIX+msg)
    
class C2CException(Exception):
    pass
    
class CiscoObject():
    """
    Abstract class for all Cisco objects
    """
    name = None
    desc = None
    color = None
    alias = []          # Alias name used to keep associations when objects
                        # are merged from IP addresses.
    dbClass = None      # Used to determine checkpoint class    
                        # Ex: 
    alreadyExist = False# Determine if it already exist in checkpoint database
    c2c = None          # Reference to c2c object (parent) 
    ciscoLines = []     # Cisco line that was used to import the object 
                        #   (useful for --verify)
    
    def __init__(self, c2c, ciscoLine, name, desc='', alreadyExist=False, \
                color=None):
        if name is None or name == '':
            raise C2CException('Invalid object. Check parsing of line: %s'\
                               % ciscoLine)
        n = copy.deepcopy(name)
        self.name = self._sanitizeIllegalWords(self._sanitizeName(name))
        self.ciscoLines = []
        self.ciscoLines.append(ciscoLine)
        self.desc = desc
        self.c2c = c2c
        self.alias = []
        self.addAlias(n)
        self.alreadyExist = alreadyExist
        if color is not None:
            self.color = color
        else:
            self.color = 'black'
        
    def __str__(self):
        return str(self.toString())
        
    def _parseChildren(self,parent):
        ret = {}
        for child in parent.children:
            a = child.text.split(' ', 2)
            if ret.has_key(a[1]):
                ret[a[1]].append(a[2])
            else:
                ret[a[1]] = []
                ret[a[1]].append(a[2])
        return ret
        
    def _sanitizeIllegalWords(self, text):
        for i, j in ILLEGAL_DIC.iteritems():
            text = text.replace(i, j)
        return text.rstrip()
        
    def _sanitizeName(self, name):
        if name != '' and name[0].isdigit():
            if isinstance(self, CiscoNet):
                return NEW_NET_PREFIX+name
            elif isinstance(self, CiscoRange):
                return NEW_RANGE_PREFIX+name
            elif isinstance(self, (CiscoName, CiscoHost)):
                return NEW_HOST_PREFIX+name
            elif isinstance(self, (CiscoServiceGroup, CiscoNetGroup)): 
                return NEW_GROUP_PREFIX+name
            elif isinstance(self,(CiscoServicePort,CiscoServiceRange)) \
                 and self.proto == 'tcp':
                return TCP_PREFIX+name
            elif isinstance(self,(CiscoServicePort,CiscoServiceRange)) \
                 and self.proto == 'udp':
                return UDP_PREFIX+name
            elif isinstance(self, (CiscoServicePort,CiscoServiceRange)) \
                 and self.proto == 'tcp-udp':
                return TCPUDP_PREFIX+name
            else:
                return name
        else:
            return name
            
    def getClass(self):
        return self.__class__.__name__
        
    def getDesc(self):
        if self.desc == None or self.desc == '':
            return ''
        else:
            return self.desc.replace('"\/ ', '').replace(' \/"', '')
            
    def getVerify(self):
        if len(self.ciscoLines) == 0:
            return ''
        else:
            ret = ''
            for line in self.ciscoLines:
                if line != None:
                    ret += " Verify: %s \n" % str(line)
            return ret
            
    def addAlias(self,text,indent=''):
        if text != None and text != self.name and not text in self.alias:
            print_debug(indent+'Adding Alias "%s" on object "%s"' 
                        % (text, str(self.name)))
            self.alias.append(text)
    
    def addCiscoLine(self,text,indent=''):
        if text != None and not text in self.ciscoLines:
            print_debug(indent+'Adding CiscoLine "%s" on object "%s"' 
                        % (text, str(self.name)))
            self.ciscoLines.append(text)

    def setColor(self, color):
        self.color = color
        
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+'(name=%s,desc=%s)' % (self.name,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret
        
    def toDBEdit(self):
        return ''    
        
    def toDBEditElement(self, groupName):
        return ''
        
class CiscoService(CiscoObject):
    """
    Abstract class for all services
    """
    proto = None
    
    def __init__(self, c2c, name, desc, alreadyExist=False):
        CiscoObject.__init__(self, c2c, None, name, desc, 
                             alreadyExist=alreadyExist)
        
    def _toDBEditType(self):
        if self.proto == 'tcp':
            return 'tcp_service'
        elif self.proto == 'udp':
            return 'udp_service'
        elif self.proto == 'any':
            return ''
        else:
            raise C2CException('Protocol not supported: %s' % self.proto)
            
    def _convertPort(self, text):
        text = str(text)
        for i, j in PORT_DIC.iteritems():
            #text = text.replace(i, j)
            text = re.sub(r'^'+i+'$', j, text)
        return text.rstrip()
        
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, 
                                                                  self.name)


class CiscoGroup(CiscoObject):                
    """
    Abstract class for all groups
    """
    members = []
    
    def __init__(self, c2c, ciscoLine, name, members=None, desc=None, \
                 alreadyExist=False, color=None):
        self.members = []       # DO NOT DELETE THIS LINE.
        CiscoObject.__init__(self, c2c, ciscoLine, name, desc, alreadyExist, \
                            color)
        if members != None:
            self.members = members
        
    def __eq__(self, other):
        if other is not None:
            return self.__dict__ == other.__dict__
        else:
            return False
        
    def _convertProto(self, text):
        if text != None:
            for i, j in PROTO_DIC.iteritems():
                text = re.sub(r'^'+i+'$', j, text)
            return text.rstrip().lower()

    def _convertPort(self, text):
        if not text.isdigit():
            text = str(text)
            for i, j in PORT_DIC.iteritems():
                text = re.sub(r'^%s$'%i, j, text)
        return text.rstrip()

    def hostmask2netmask(self,hostmask):
        mask_bytes = hostmask.split('.',3)
        mask_bytes = [str(int(b) ^ 255) for b in mask_bytes]
        return '.'.join(mask_bytes)
                    
    def _getMemberObj(self, type, v1, v2=None, v3=None):
        if type == 'host' and v1 == 'any':
            name = v1
            obj_list = self.c2c.findObjByName(name)
        elif type in SUPPORTED_IP_PROTO and v1 == 'any':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoAnyPort')
        elif type == 'icmp' or type == 'icmp-object':
            name = v1
            obj_list = self.c2c.findIcmpByName(name)
        elif type == 'ospf':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoOspfProto')
        elif type == 'esp':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoEspProto')
        elif type in ['ah','ahp']:
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoAHProto')
        elif type == 'vrrp':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoVrrpProto')
        elif type == 'skip':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoSkipProto')
        elif type == 'gre':
            name = v1
            obj_list = self.c2c.findObjByNameType(name,'CiscoGreProto')
        elif type == 'host':
            name = v1
            #obj_list = self.c2c.findHostByAddr(name)
            if not isipaddress(name):
                obj_list = self.c2c.findObjByName(name)
            else:
                obj_list = self.c2c.findHostByAddr(name)
        elif type == 'protocol':
            name = v1
            obj_list = self.c2c.findIcmpByName(name)
        elif type == 'subnet':
            name,subnet,mask = v1,v1,v2
            obj_list = self.c2c.findNetByAddr(subnet,mask)
        elif type == 'object' or type == 'object-group':
            name = v1
            obj_list = self.c2c.findObjByName(name)
        elif type == 'port-group' or type == 'port-object':
            name = v1
            obj_list = self.c2c.findServiceByName(name)
        elif type == 'eq':        # port-object eq X
            name = "%s/%s" % (v1,v2)
            proto,port = v1,v2
            port = self._convertPort(port)
            if proto in ['tcp','udp']:
                obj_list = self.c2c.findServiceByNum(proto,port)
            elif proto == 'tcp-udp':
                # Return None if one of tcp or udp port cannot be found.
                # _createMemberObj() will take care of adding only the one
                # missing
                obj_list1 = self.c2c.findServiceByNum('tcp',port)
                obj_list2 = self.c2c.findServiceByNum('udp',port)
                ret1 = self._parseResult(obj_list1, name, type)
                ret2 = self._parseResult(obj_list2, name, type)
                if ret1 and ret2:
                    return [ret1,ret2]
                else:
                    return None                    
            else:
                print_msg("_getMemberObj: %s %s %s %s" % (type,v1,v2,v3))
                raise C2CException('Cannot search a port without a protocol.')
        elif type == 'range':        # port-object range X Y
            name = "%s/%s-%s" % (v1,v2,v3)
            proto = v1
            first = self._convertPort(v2)
            last = self._convertPort(v3)
            if proto in ['tcp','udp']:
                obj_list = self.c2c.findServiceByRange(proto,first,last)
            elif proto == 'tcp-udp':
                obj_list1 = self.c2c.findServiceByRange('tcp',first,last)
                obj_list2 = self.c2c.findServiceByRange('udp',first,last)
                ret1 = self._parseResult(obj_list1, name, type)
                ret2 = self._parseResult(obj_list2, name, type)
                if ret1 and ret2:
                    return [ret1,ret2]
                else:
                    return None
            else:
                print_msg("_getMemberObj: %s %s %s %s" % (type,v1,v2,v3))
                raise C2CException('Cannot search a port range without a protocol.')
        elif type in ['static', 'dynamic']:                # Nat rules
            name = v1
            obj_list = self.c2c.findObjByName(name)
        else:
            print_msg("_getMemberObj: %s %s %s %s" % (type,v1,v2,v3))
            raise C2CException('Object type "%s" is not supported.' % type)
                        
        return self._parseResult(obj_list, name, type)

    def _parseResult(self,obj_list, name, type):
        if len(obj_list) == 1: 
            return obj_list[0]
        elif len(obj_list) > 1:
            print_debug('Warning: Found %i instances of "%s" (%s)'
                        % (len(obj_list),name,type))
            for obj in obj_list:
                print_debug(obj.toString('  '))
            return obj_list[0]
        else:
            print_debug('Warning: Could not find object "%s" (%s). '
                        'The script will create it.' % (name,type))
            return None
            
    def _createMemberObj(self, type, v1, v2=None, v3=None):
        if type == 'host' and v1 == 'any':
            newObj = CiscoAnyHost(self)
            self.c2c.addObj(newObj)
        elif type in SUPPORTED_IP_PROTO and v1 == 'any':
            newObj = CiscoAnyPort(self)
            self.c2c.addObj(newObj)
        elif type == 'ospf' and v1 == 'any':
            newObj = CiscoOspfProto(self)
            self.c2c.addObj(newObj)
        elif type == 'esp' and v1 == 'any':
            newObj = CiscoEspProto(self)
            self.c2c.addObj(newObj)
        elif type in ['ah','ahp'] and v1 == 'any':
            newObj = CiscoAHProto(self)
            self.c2c.addObj(newObj)
        elif type == 'vrrp' and v1 == 'any':
            newObj = CiscoVrrpProto(self)
            self.c2c.addObj(newObj)
        elif type == 'skip' and v1 == 'any':
            newObj = CiscoSkipProto(self)
            self.c2c.addObj(newObj)
        elif type == 'gre' and v1 == 'any':
            newObj = CiscoGreProto(self)
            self.c2c.addObj(newObj)
        elif type == 'icmp' and v1 == 'any':
            newObj = CiscoAnyIcmp(self)
            self.c2c.addObj(newObj)
        elif type == 'icmp' or type == 'icmp-object':
            name = v1
            newObj = CiscoIcmp(self, name)
            self.c2c.addObj(newObj)
        elif type == 'host':
            name = v1
            if not isipaddress(name):
                names = self.c2c.findNameByName(v1)

                # Check if a CiscoName exists with same IP. If so, overwrite the IP.
                if len(names) == 1:
                    ipAddr = names[0].ipAddr
                    desc = names[0].desc
                elif len(names) > 1:
                    ipAddr = names[0].ipAddr
                    desc = names[0].desc
                    print_debug('WARNING: More than one name found with IP %s. The first occurence is taken.' % ipAddr)
                else:
                    raise C2CException('The name %s was not found.' % name)

                newObj = CiscoHost(self.c2c, None, name, ipAddr, desc, \
                                   color=self.c2c.color)
            else:
                names = self.c2c.findNameByAddr(v1)

                # Check if a CiscoName exists with same IP. If so, overwrite the name and description.
                if len(names) == 1:
                    name = names[0].name
                    ipAddr = v1
                    desc = names[0].desc
                elif len(names) > 1:
                    name = names[0].name
                    ipAddr = v1
                    desc = names[0].desc
                    print_debug('WARNING: More than one name found with IP %s. The first occurence is taken.' % ipAddr)
                else:
                    name = NEW_HOST_PREFIX+v1
                    ipAddr = v1
                    desc = None
                    print_debug('No name found for IP %s. Using default naming convention' % ipAddr)
                newObj = CiscoHost(self.c2c, None, name, ipAddr, desc, \
                                   color=self.c2c.color)

            self.c2c.hostCrCt += 1
            self.c2c.addObj(newObj)
        elif type == 'subnet':
            subnet,mask = v1,v2
            cidr = str(mask2cidr(mask))
            newObj = CiscoNet(self, None, NEW_NET_PREFIX+subnet+'-'+cidr, \
                         subnet, mask, color=self.c2c.color)
            self.c2c.netCrCt += 1
            self.c2c.addObj(newObj)
        elif type == 'eq':        # port-object eq X
            proto,port = v1,v2
            port = self._convertPort(port)
            if proto in ['tcp','udp']:
                newObj = CiscoServicePort(self, None, None, proto, port)
                self.c2c.singlePortCrCt += 1
                self.c2c.addObj(newObj)
            elif proto == 'tcp-udp':
                name = "%s/%s" % (v1,v2)
                proto,port = v1,v2
                obj_list1 = self.c2c.findServiceByNum('tcp',port)
                obj_list2 = self.c2c.findServiceByNum('udp',port)
                ret1 = self._parseResult(obj_list1, name, 'tcp')
                ret2 = self._parseResult(obj_list2, name, 'udp')
                
                if ret1 == None:
                    newObj = CiscoServicePort(self, None, None, 'tcp', port)
                    self.c2c.singlePortCrCt += 1
                    self.c2c.addObj(newObj)
                if ret2 == None:
                    newObj = CiscoServicePort(self, None, None, 'udp', port)
                    self.c2c.singlePortCrCt += 1
                    self.c2c.addObj(newObj)
        elif type == 'range':        # port-object range X Y
            proto = v1
            first = self._convertPort(v2)
            last = self._convertPort(v3)
            if proto in ['tcp','udp']:            
                newObj = CiscoServiceRange(self, None, None, proto, first, last)
                self.c2c.portRangeCrCt += 1
                self.c2c.addObj(newObj)
            elif proto == 'tcp-udp':
                newObj = CiscoServiceRange(self, None, None, 'tcp', first, last)
                self.c2c.portRangeCrCt += 1
                self.c2c.addObj(newObj)

                newObj = CiscoServiceRange(self, None, None, 'udp', first, last)
                self.c2c.portRangeCrCt += 1
                self.c2c.addObj(newObj)
# TEMPORARY COMMENTED
# TODO: Fully support NAT rules
#        elif type in ['static', 'dynamic']:                # Nat rules
#            name = v1
#            newObj = CiscoHost(self, None, name, name, None, True, \
#                               color=self.c2c.color)
#            self.c2c.addObj(newObj)
#            self.c2c.hostCrCt += 1
#            #raise C2CException('Cannot create a nat external IP "%s" on the fly.' % name)
        elif type == 'object' or type == 'object-group':
            raise C2CException('Cannot create an object member "%s" on the fly.' % v1)
        elif type == 'port-group':
            raise C2CException('Cannot create a port group member "%s" on the fly.' % v1)
        else:
            raise C2CException('Invalid type: %s' % type)
        return newObj

    def _getOrCreateMemberObj(self,type,v1,v2=None,v3=None):
        obj = self._getMemberObj(type,v1,v2,v3)
        if obj is None:
            self._createMemberObj(type,v1,v2,v3)
            obj = self._getMemberObj(type,v1,v2,v3)
            if obj is None:
                raise C2CException('Could not create member: %s %s %s %s' % (type,v1,v2,v3))
        return obj

    def _getOrFailMemberObj(self,type,v1,v2=None,v3=None):
        obj = self._getMemberObj(type,v1,v2,v3)
        if obj == None:
            raise C2CException('Could not find mandatory "%s" object '\
                               'named "%s" for group %s' % (type,v1,self.name))
        return obj
        
    def _getAndAddMemberObj(self,type,v1,v2=None,v3=None):
        obj = self._getOrFailMemberObj(type,v1,v2,v3)
        self.addMember(obj)
        return obj

    def addMember(self, obj, new=False):
        if isarray(obj):
            for o in obj:
                self.addMember(o)
        elif obj is not None:
            print_debug('Adding member %s to group %s' %(obj.name,self.name))
            self.members.append(obj)
        else:
            raise C2CException('Attempting to add a None object to group %s'\
                              % self.name)
        
class CiscoName(CiscoObject):
    """A cisco name"""
    ipAddr = None
    
    def __init__(self, c2c, parsedObj, name=None, ipAddr=None, desc=None, \
                 alreadyExist=False, color=None):
        if parsedObj.__class__.__name__ == 'ASAName':
            print_debug(str(parsedObj))
            name = parsedObj.name
            self.ipAddr = parsedObj.addr
            desc = parsedObj.desc
            CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                                color)
        elif parsedObj.__class__.__name__ == 'ASACfgLine':
            print_debug('The following line was not parsed as a ASAName: %s' % str(parsedObj))
        elif parsedObj is None:
            self.ipAddr = ipAddr

        CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                             color)
        self.dbClass = 'host_plain'
            
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,ipAddr=%s,desc=%s,alias=%s)\n" % (self.name,self.ipAddr,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return ''

    def toDBEditElement(self, groupName):
        return ''


class CiscoHost(CiscoName):
    """A cisco host"""
    
    def __init__(self, c2c, parsedObj, name=None, ipAddr=None, desc=None, \
                 alreadyExist=False, color=None):
        if parsedObj != None:
            name = parsedObj.name
            desc = parsedObj.description
            mm_r = parsedObj.result_dict
            ipAddr = mm_r['ipaddr']

        CiscoName.__init__(self, c2c, None, name, ipAddr, desc, \
                           alreadyExist, color)
        
    def toDBEdit(self):
        return '# Creating new host: {0}\n'\
                'create host_plain {0}\n'\
                'modify network_objects {0} ipaddr {1}\n'\
                'modify network_objects {0} comments "{2}"\n'\
                'modify network_objects {0} color "{3}"\n'\
                'update network_objects {0}\n'\
                .format(self.name, self.ipAddr, self.getDesc(), self.color)

    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoAnyHost(CiscoHost):
    """A cisco host"""
    
    def __init__(self, c2c):
        CiscoHost.__init__(self, c2c, None, 'any', None, None, True)
        
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' globals:any\n".format(groupName)
        
class CiscoNet(CiscoObject):
    """A cisco subnet"""
    ipAddr = None
    mask = None
    
    def __init__(self, c2c, parsedObj, name=None, ipAddr=None, mask=None, \
                 desc=None, alreadyExist=False, color=None):

        if parsedObj != None:
            name = parsedObj.name
            desc = parsedObj.description
            mm_r = parsedObj.result_dict
            self.ipAddr = mm_r['ipaddr']
            self.mask = mm_r['mask']
        else:
            self.ipAddr = ipAddr
            self.mask = mask

        CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                            color)
        self.dbClass = 'network'
            
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,ipAddr=%s/%s,desc=%s,alias=%s)\n"\
                % (self.name,self.ipAddr,self.mask,self.getDesc(),\
                   ';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '# Creating new subnet: {0}\n'\
                'create network {0}\n'\
                'modify network_objects {0} ipaddr {1}\n'\
                'modify network_objects {0} netmask {2}\n'\
                'modify network_objects {0} comments "{3}"\n'\
                'modify network_objects {0} color "{4}"\n'\
                'update network_objects {0}\n'\
                .format(self.name, self.ipAddr, self.mask, \
                        self.getDesc(), self.color)
        
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n"\
                .format(groupName, self.name)

class CiscoRange(CiscoObject):
    """A cisco range"""
    first = None
    last = None
    
    def __init__(self, c2c, parsedObj, name=None, ipAddrFirst=None, \
                 ipAddrLast=None, desc=None, alreadyExist=False, color=None):

        if portObj != None:
            name = parsedObj.name
            desc = parsedObj.description
            mm_r = parsedObj.result_dict
            self.first = mm_r['ipaddr_low']
            self.last = mm_r['ipaddr_high']
        else:
            self.first = ipAddrFirst
            self.last = ipAddrLast

        CiscoObject.__init__(self, c2c, None, name, desc, \
                             alreadyExist, color)

        self.dbClass = 'address_range'
            
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,ipRange=%s/%s,desc=%s)\n" % (self.name,self.first,self.last,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '# Creating new range: {0}\n'\
                'create address_range {0}\n'\
                'modify network_objects {0} ipaddr_first {1}\n'\
                'modify network_objects {0} ipaddr_last {2}\n'\
                'modify network_objects {0} comments "{3}"\n'\
                'modify network_objects {0} color "{4}"\n'\
                'update network_objects {0}\n'\
                .format(self.name, self.first, self.last, \
                        self.getDesc(), self.color)        
        
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoServicePort(CiscoService):
    """A cisco name"""
    port = ''
    src_port = ''
    
    def __init__(self, c2c, parsedObj, name=None, proto=None, port=None, \
                 desc=None, alreadyExist=False):
        # if built from ciscoconfparse
        if parsedObj != None:
            name = parsedObj.name
            desc = parsedObj.description
            mm_r = parsedObj.result_dict
            self.proto = mm_r['proto']
            self.port = self._convertPort(mm_r['dst_port'])
            self.src_port = self._convertPort(mm_r['src_port'] or '')
            CiscoService.__init__(self, c2c, name, desc, alreadyExist)

        # if the port is dynamically created, no name will be specified
        else:
            self.proto = proto
            self.port = self._convertPort(port)
            self.src_port = ''
            if name == None:
                if proto == 'tcp':
                    CiscoService.__init__(self, c2c, TCP_PREFIX+port, desc, alreadyExist)
                    self.dbClass = 'tcp_service'
                elif proto == 'udp':
                    CiscoService.__init__(self, c2c, UDP_PREFIX+port, desc, alreadyExist)
                    self.dbClass = 'udp_service'
                else:
                    raise C2CException('Invalid Protocol: %s' % proto)
            else:
                CiscoService.__init__(self, c2c, name, desc, alreadyExist)
                    
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        if self.src_port == '':
            ret = prefix+"(name=%s,port=%s,desc=%s,alias=%s)\n"\
                    % (self.name,self.port,self.getDesc(),';'.join(self.alias))
        else:
            ret = prefix+"(name=%s,port=%s,src_port=%s,desc=%s,alias=%s)\n"\
                    % (self.name,self.port,self.src_port,self.getDesc(),\
                       ';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        # if no source port is specified (most of the case)
        if self.src_port == '':
            return '# Creating new port: {1}\n'\
                    'create {0} {1}\n'\
                    'modify services {1} port {2}\n'\
                    'modify services {1} comments "{3}"\n'\
                    'update services {1}\n'\
                    .format(self._toDBEditType(), self.name, self.port,\
                            self.getDesc())
        else:
            return '# Creating new port with source : {1}\n'\
                    'create {0} {1}\n'\
                    'modify services {1} port {2}\n'\
                    'modify services {1} src_port {4}\n'\
                    'modify services {1} comments "{3}"\n'\
                    'update services {1}\n'\
                    .format(self._toDBEditType(), self.name, self.port,\
                    self.getDesc(), self.src_port)
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoAnyPort(CiscoServicePort):
    """A cisco port"""
    
    def __init__(self, c2c):
        CiscoServicePort.__init__(self, c2c, None, 'any', None, 0, None, True)
        
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' globals:any\n".format(groupName)
        
class CiscoServiceRange(CiscoService):
    """A cisco name"""
    src_first = None
    src_last = None
    first = None
    last = None
    
    def __init__(self, c2c, parsedObj, name=None, proto=None, first=None, last=None, desc=None, alreadyExist=False):
        # if built from ciscoconfparse
        if parsedObj != None:
            name = parsedObj.name
            desc = parsedObj.description
            mm_r = parsedObj.result_dict
            self.proto = mm_r['proto']
            self.first = mm_r['dst_port_low']
            self.last = mm_r['dst_port_high']
            self.src_first = mm_r['src_port_low']
            self.src_last = mm_r['src_port_high']
            CiscoService.__init__(self, c2c, name, desc, alreadyExist)

        # if the port is dynamically created, no name will be specified
        else:
            self.proto = proto
            self.first = first
            self.last = last
            self.src_first = ''
            self.src_last = ''
            if name == None:
                if proto == 'tcp':
                    CiscoService.__init__(self, c2c, TCP_PREFIX+first+'-'+last,\
                                          desc, alreadyExist)
                elif proto == 'udp':
                    CiscoService.__init__(self, c2c, UDP_PREFIX+first+'-'+last,\
                                          desc, alreadyExist)        
                else:
                    raise C2CException('Invalid Protocol: %s' % proto)
            else:
                CiscoService.__init__(self, c2c, name, desc, alreadyExist)
        
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        if self.src_first == '' or self.src_last == '':
            ret = prefix+"(name=%s,port=%s-%s,desc=%s)\n"\
                    % (self.name,self.first,self.last,self.getDesc())
        else:
            ret = prefix+"(name=%s,port=%s-%s,src_port=%s-%s,desc=%s)\n"\
                    % (self.name,self.first,self.last,self.src_first,\
                       self.src_last,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret
        
    def toDBEdit(self):
        # if no source port is specified (most of the case)
        if self.src_first == '' or self.src_last == '':
            return '# Creating new port range: {1}\n'\
                    'create {0} {1}\n'\
                    'modify services {1} port {2}-{3}\n'\
                    'modify services {1} comments "{4}"\n'\
                    'update services {1}\n'\
                    .format(self._toDBEditType(), self.name, self.first,\
                            self.last, self.getDesc())
        else:
            return '# Creating new port range: {1}\n'\
                    'create {0} {1}\n'\
                    'modify services {1} port {2}-{3}\n'\
                    'modify services {1} src_port {5}-{6}\n'\
                    'modify services {1} comments "{4}"\n'\
                    'update services {1}\n'\
                    .format(self._toDBEditType(), self.name, self.first,\
                            self.last, self.getDesc(), self.src_first,\
                           self.src_last)
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoProto(CiscoService):
    """A cisco icmp packet"""
    
    def __init__(self, c2c, name=None, desc=None, alreadyExist=False):
        CiscoService.__init__(self, c2c, name, alreadyExist)
        self.desc = desc

    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,desc=%s,alias=%s)\n" \
                     % (self.name,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return ''
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)
        
class CiscoIcmp(CiscoProto):
    """A cisco icmp packet"""
    
    def __init__(self, c2c, name=None, desc=None, alreadyExist=False):
        CiscoProto.__init__(self, c2c, name, desc, alreadyExist)
        self.dbClass = 'icmp_service'
        
class CiscoAnyIcmp(CiscoProto):
    """A cisco icmp packet"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_ICMP, None, True)
        self.addAlias('any')
    
class CiscoOspfProto(CiscoProto):
    """A cisco OSPF protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_OSPF, None, True)
        self.addAlias('any')

class CiscoEspProto(CiscoProto):
    """A cisco ESP protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_ESP, None, True)
        self.addAlias('any')
        
class CiscoAHProto(CiscoProto):
    """A cisco AH protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_AH, None, True)
        self.addAlias('any')
        
class CiscoVrrpProto(CiscoProto):
    """A cisco VRRP protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_VRRP, None, True)
        self.addAlias('any')

class CiscoSkipProto(CiscoProto):
    """A cisco SKIP protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_SKIP, None, True)
        self.addAlias('any')

class CiscoGreProto(CiscoProto):
    """A cisco GRE protocol"""
    
    def __init__(self, c2c):
        CiscoProto.__init__(self, c2c, ANY_GRE, None, True)
        self.addAlias('any')

class CiscoNetGroup(CiscoGroup):
    """A cisco subnet"""
    
    def __init__(self, c2c, parsedObj, name=None, members=None, desc=None, \
                 alreadyExist=False, color=None):

        if parsedObj != None:
            name = parsedObj.name
            desc = parsedObj.description

            CiscoGroup.__init__(self, c2c, parsedObj, name, None, desc, \
                                alreadyExist, color)
            for mm_r in parsedObj.result_dict:
                if 'member_method' in mm_r.keys():
                    mem_method = mm_r['member_method']
                else:
                    mem_method = None
                if mem_method == 'host':
                    ipaddr = mm_r['ipaddr']
                    net_obj = self._getOrCreateMemberObj(mem_method,ipaddr)
                    self.addMember(net_obj)
                elif mem_method == 'subnet':
                    subnet = mm_r['subnet']
                    mask = mm_r['mask']
                    net_obj = self._getOrCreateMemberObj(mem_method,subnet,mask)
                    self.addMember(net_obj)
                elif mem_method == 'group-object' or mem_method == 'object':
                    obj_name = mm_r['object_name']
                    net_obj = self._getOrFailMemberObj('object',obj_name)
                    self.addMember(net_obj)
                elif mem_method == 'description':
                    pass
                elif mem_method == None:
                    print_msg('A null member was identifed in object "%s"' % parsedObj.text)
                else:
                    raise C2CException('Unsupported group member method: %s'\
                                      % mem_method)
        else:
            CiscoGroup.__init__(self, c2c, None, name, members, desc, \
                                alreadyExist, color)
        self.dbClass = 'network_object_group'
            
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,desc=%s,nbMembers=%i,alias=%s)\n" % (self.name,self.getDesc(),len(self.members),';'.join(self.alias))
        for member in self.members:
            ret += indent+member.toString(indent+' ')
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        ret = '# Creating new network group: {0}\n'\
                'create network_object_group {0}\n'\
                'modify network_objects {0} comments "{1}"\n'\
                'modify network_objects {0} color "{2}"\n'\
                .format(self.name, self.getDesc(), self.color)
        for mem in self.members:
            ret += mem.toDBEditElement(self.name)
        ret += 'update network_objects {0}\n'.format(self.name)
        return ret

    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoProtoGroup(CiscoGroup):
    """A cisco proto group"""
    
    def __init__(self, c2c, parsedObj):
        name = parsedObj.name
        desc = parsedObj.description
        CiscoGroup.__init__(self, c2c, parsedObj, name, None, desc)
        self.dbClass = 'service_group'

        # TODO: Check the potential of protocol groups in Cisco groups
        # Currently support only what is needed: convert tcp+udp and ip 
        # to "any ports"
        mm_r = parsedObj.result_dict
        if ('tcp' in mm_r and 'udp' in mm_r) \
              or 'ip' in mm_r:
            obj = self._getOrCreateMemberObj('ip','any')
            obj.addAlias(name)
            self.addMember(obj)
        
    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,desc=%s,nbMembers=%i)\n" % (self.name,self.getDesc(),len(self.members))
        for member in self.members:
            ret += indent+' '+member.toString(indent)
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        ret = '# Creating new port group: {0}\n'\
                'create service_group {0}\n'\
                'modify services {0} comments "{1}"\n'\
                'modify services {0} color "{2}"\n'\
                .format(self.name, self.getDesc(), self.color)
        for mem in self.members:
            ret += mem.toDBEditElement(self.name)
        ret += 'update services {0}'.format(self.name)
        return ret
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)
    
class CiscoServiceGroup(CiscoGroup):
    """A cisco service"""
    
    def __init__(self, c2c, parsedObj):
        name = parsedObj.name
        desc = parsedObj.description
        CiscoGroup.__init__(self, c2c, parsedObj, name, None, desc)
        self.dbClass = 'service_group'

        for mm_r in parsedObj.result_dict:
            obj = self._parse_member(mm_r)
            self.addMember(obj)

    def _parse_member(self,mm_r):
        """
        Return a list of service object by evaluatig proto and port 
        attributes of the result dictionary mm_r
        """
        proto = self._convertProto(mm_r['proto'])
        proto_m = mm_r['proto_method']
        port = mm_r['dst_port']
        port_m = mm_r['dst_port_method']

        # if no proto, check if specified in parent
        # Possible values of port-object:
        #   port-object range 8194 8198
        #   port-object eq 4321
        #   port-object eq whois
        # Possible values of service-object:
        #   service-object tcp destination range 19305 19309 
        #   service-object udp destination eq 123
        #   service-object udp destination eq whois
        if proto_m == 'port-object' or proto_m == 'service-object':
            if port_m == 'eq':
                portList = port.split(' ')
                ret = list()
                for p in portList:
                    ret.append(self._getOrCreateMemberObj(port_m,proto,p))
                return ret
            elif port_m in ['neq','lt','gt']:
                raise C2CException('Port method "%s" not implemented yet.' % \
                                  port_m)
            elif port_m == 'range':
                first,last = port.split(' ',1)
                return [self._getOrCreateMemberObj(port_m,proto,first,last)]
            elif port_m == 'object-group' or port_m == 'object':
                return [self._getOrFailMemberObj('port-group',port)]
            elif port_m == None:        # this means any
                return [self._getAnyPort(proto)]
            else:
                raise C2CException('Invalid port-object: %s' % mm_r)
        # Possible values of object:
        #   service-object object TCP_4443
        # Possible values of group-object:
        #   group-object RPC_High_ports_TCP
        elif proto_m == 'object' or proto_m == 'group':
            obj = self._getOrFailMemberObj('port-group',port)
            return [obj]
        # Possible values of protocol:
        #   service-object icmp|ip|tcp|udp
        elif proto_m == 'protocol':
            if proto in SUPPORTED_IP_PROTO:
                return [self._getOrCreateMemberObj('ip','any')]
            elif proto in SUPPORTED_NO_IP_PROTO:
                return [self._getOrCreateMemberObj(proto,'any')]
#        elif proto_m == 'proto-group'
#            return [self._getOrCreateMemberObj('port-object','any')]
        # Possible values of group-object:
        #   icmp-object echo-reply
        #   icmp-object time-exceeded
        #   icmp-object unreachable
        #   icmp-object echo
        elif proto_m == 'icmp':
            return [self._getOrCreateMemberObj('icmp',port)]
        else:
            print_debug(mm_r)
            raise C2CException("Unrecognized proto/port")

    def toString(self, indent='', verify=False):
        prefix = indent+self.getClass()
        ret = prefix+"(name=%s,desc=%s,nbMembers=%i)\n" % (self.name,self.getDesc(),len(self.members))
        for member in self.members:
            ret += indent+' '+member.toString(indent)
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        ret = '# Creating new port group: {0}\n'\
                'create service_group {0}\n'\
                'modify services {0} comments "{1}"\n'\
                'modify services {0} color "{2}"\n'\
                .format(self.name, self.getDesc(), self.color)
        for mem in self.members:
            ret += mem.toDBEditElement(self.name)
        ret += 'update services {0}\n'.format(self.name)
        return ret
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

# Doc: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk39327
#    => Notes about NAT on load sharing vs high availability
class CiscoNatRule(CiscoGroup):

    """A cisco nat object"""
    installOn = None
    type = None            # static, dynamic, hide
    internalObj = None
    externalObj = None
    
    def __init__(self, c2c, parsedObj, installOn):
        cmd,id,nattedObjName = parsedObj.text.split(' ', 2)
        CiscoGroup.__init__(self, c2c, parsedObj.text, nattedObjName)
        self.dbClass = ''
        self.installOn = installOn
        
        obj = self._getOrFailMemberObj('object',nattedObjName)
        
        child = self._parseChildren(parsedObj)
        # For all network objects
        if child.has_key('nat'):
            for network in child['nat']:
                # Possible values of network-object:
                # nat (dmz-1,SCNET) dynamic 205.192.153.9
                # nat (inside,SCNET) dynamic obj-205.192.153.10-205.192.153.254
                # nat (dmz-1,outside) static 69.17.147.172
                # nat (DMZ,outside) dynamic interface
                #
                # Does not support:
                # nat (dmz-1,outside) static 1.2.3.4 service tcp 8089 8089
                
                zones,type,natIp = network.split(' ',2)
                if type == 'dynamic' and natIp == 'interface':
                    type = 'hide'
                elif type == 'static' and isipaddress(natIp) and not ' ' in natIp:
                    obj = self._getOrCreateMemberObj(type,natIp)
                    self.externalObj = obj
                else:
                    raise C2CException('Unsupported NAT rule: %s' % network)
                    
                self.type = type
                
        if child.has_key('description'):
            self.desc = child['description'][0]
        
    def toString(self, indent='', verify=False):
        extName = ''
        if self.externalObj != None: 
            extName = self.externalObj.name 
        prefix = indent+self.getClass()
        ret = prefix+"(Type=%s,InternalIP=%s,ExternalIP=%s,alias=%s)\n" % (self.type,self.internalObj.name,extName,';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        if self.type == 'hide':
            return '# Creating new nat rule: {0}\n'\
            'modify network_objects {0} add_adtr_rule true\n'\
            'modify network_objects {0} NAT NAT\n'\
            'modify network_objects {0} NAT:valid_addr_name {0}\n'\
            'modify network_objects {0} NAT:valid_ipaddr 0.0.0.0\n'\
            'modify network_objects {0} NAT:valid_ipaddr6 ::\n'\
            'modify network_objects {0} NAT:netobj_adtr_method adtr_hide\n'\
            'modify network_objects {0} NAT:the_firewalling_obj network_objects:{1}\n'\
            'update network_objects {0}\n'\
            .format(self.internalObj.name, self.installOn)
        else:
            return '# Creating new nat rule: {0}\n'\
            'modify network_objects {0} add_adtr_rule true\n'\
            'modify network_objects {0} NAT NAT\n'\
            'modify network_objects {0} NAT:valid_ipaddr {1}\n'\
            'modify network_objects {0} NAT:netobj_adtr_method adtr_static\n'\
            'modify network_objects {0} NAT:the_firewalling_obj network_objects:{2}\n'\
            'update network_objects {0}\n'\
            .format(self.internalObj.name, self.externalObj.ipAddr, self.installOn)

    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

# Doc: https://sc1.checkpoint.com/documents/R77/CP_R77_CLI_ReferenceGuide_WebAdmin/105997.htm
class CiscoACLRule(CiscoGroup):
    src = None
    dst = None
    port = None
    action = None
    time = None
    tracks = None
    installOn = None
    policy = DEFAULT_POLICY
    disabled = False
    
    def __init__(self, c2c, parsedObj, remark=None, policy=None,\
                 installOn=None, forceLog=None):
        name = parsedObj.name
        CiscoGroup.__init__(self, c2c, parsedObj, name, None, remark)
        self.policy = policy
        self.installOn = installOn
        self.src = []
        self.dst = []
        self.port = []
        self._buildFromParsedObj(parsedObj)
        if forceLog:
            self.tracks = True
    
    def _buildFromParsedObj(self, parsedObj):
        """
        parsedObj attributes:
            - action
            - remark
            - proto
            - proto_method
            - src_addr
            - src_hostmask
            - src_addr_method
            - src_port
            - src_port_method
            - dst_addr
            - dst_hostmask
            - dst_addr_method
            - dst_port
            - dst_port_method

        src_addr_method & dst_addr_method:
            - any
            - object-group
            - object
            - host
            - network
            - remark

        proto_method:
            - proto
            - object-group
            - remark

        src_port & dst_port: 
            - eq|neq|lt|gt
            - range
            - object-group

        proto_method:
            - 
        """
        self.action = self._getAction(parsedObj)
        self.src = self._getSrc(parsedObj)
        self.dst = self._getDst(parsedObj)
        self.port = self._getServices(parsedObj)
        self.time = self._getTime(parsedObj)
        self.tracks = self._getTracks(parsedObj)
        self.disabled = self._getDisabled(parsedObj)

    def _getAction(self, parsedObj):
        action = parsedObj.action
        if action in ['permit','deny']:
            return action
        else:
            raise C2CException('Action "%s" not supported' % action)
            
    def _getSrc(self, parsedObj):
        if parsedObj.src_addr_method == 'any':
            return [self._getAnyAddr()]
        elif parsedObj.src_addr_method == 'object-group':
            return [self._getOrFailMemberObj('object-group',parsedObj.src_addr)]
        elif parsedObj.src_addr_method == 'object':
            return [self._getOrFailMemberObj('object',parsedObj.src_addr)]
        elif parsedObj.src_addr_method == 'host':
            return [self._getOrCreateMemberObj('host',parsedObj.src_addr)]
        elif parsedObj.src_addr_method == 'network':
            if parsedObj.src_hostmask:
                netmask = self.hostmask2netmask(parsedObj.src_hostmask)
            elif parsedObj.src_netmask:
                netmask = parsedObj.src_netmask
            else:
                raise C2CException('Cannot find netmask for "%s"' % \
                                  parsedObj.text)
            return [self._getOrCreateMemberObj('subnet',parsedObj.src_addr,netmask)]
        elif parsedObj.src_addr_method == 'remark':
            return None
        elif type(parsedObj).__name__ == 'IOSAclLine' and \
             parsedObj.type == 'standard':   # standard = any Source
            return [self._getAnyAddr()]
        elif parsedObj.parent.type == 'standard':   # standard = any Source
            return [self._getAnyAddr()]

    def _getDst(self, parsedObj):
        if parsedObj.dst_addr_method == 'any':
            return [self._getAnyAddr()]
        elif parsedObj.dst_addr_method == 'object-group':
            return [self._getOrFailMemberObj('object-group',parsedObj.dst_addr)]
        elif parsedObj.dst_addr_method == 'object':
            return [self._getOrFailMemberObj('object',parsedObj.dst_addr)]
        elif parsedObj.dst_addr_method == 'host':
            return [self._getOrCreateMemberObj('host',parsedObj.dst_addr)]
        elif parsedObj.dst_addr_method == 'network':
            if parsedObj.dst_hostmask:
                netmask = self.hostmask2netmask(parsedObj.dst_hostmask)
            elif parsedObj.dst_netmask:
                netmask = parsedObj.dst_netmask
            else:
                raise C2CException('Cannot find netmask for "%s"' % \
                                  parsedObj.text)
            return [self._getOrCreateMemberObj('subnet',parsedObj.dst_addr,netmask)]
        elif parsedObj.dst_addr_method == 'remark':
            return None
        elif parsedObj.parent.type == 'standard':   # standard = any Source
            return [self._getAnyAddr()]

    def _getAnyAddr(self):
        return self._getOrCreateMemberObj('host','any')
            
    def _getServices(self,parsedObj):
        """
        Return a list of serviced by evaluatig proto and port attributes of 
        a parsed object.
        """
        proto = self._convertProto(parsedObj.proto)
        proto_m = parsedObj.proto_method
        if type(parsedObj).__name__ != 'IOSAclLine':     # IOSAclLine does not have a port
            port = parsedObj.dst_port
            port_m = parsedObj.dst_port_method
        else:
            port = None
            port_m = None
        if proto_m == 'proto':
            if port_m == 'eq':
                portList = port.split(' ')
                ret = []
                for p in portList:
                    if p != '':
                        ret.append(self._getOrCreateMemberObj(port_m,proto,p))
                return ret
            elif port_m in ['neq','lt','gt']:
                raise C2CException('Port method "%s" not implemented yet.' % \
                                  port_m)
            elif port_m == 'range':
                first,last = port.split(' ',1)
                return [self._getOrCreateMemberObj(port_m,proto,first,last)]
            elif port_m == 'object-group' or port_m == 'object':
                return [self._getOrCreateMemberObj('port-group',port)]
            elif port_m == None:        # this means any
                return [self._getAnyPort(proto)]
        elif proto_m == 'object-group':
            return [self._getOrFailMemberObj('port-group',proto)]
        elif parsedObj.parent.type == 'standard':   # standard = any
            return [self._getAnyPort('ip')]
        elif proto_m == 'remark':
            return None
        else:
            print_debug("%s" % (parsedObj.text))
            print_debug("%s %s %s %s" % (proto,proto_m,port,port_m))
            raise C2CException("Unrecognized proto/port. Add --debug for more details")
        
    def _getAnyPort(self, proto):
        if proto in SUPPORTED_IP_PROTO:
            type = 'ip'
        elif proto in SUPPORTED_NO_IP_PROTO:
            type = proto
        else:
            raise C2CException('Cannot find the "any" service for protocol "%s"' %proto)
            
        obj = self._getOrCreateMemberObj(type,'any')
        return obj

    def _getTime(self, parsedObj):
        return None
        
    def _getTracks(self, parsedObj):
        if parsedObj.log:
            return True
        else:
            return False
        
    def _getInstallOn(self, parsedObj):
        return DEFAULT_INSTALLON
        
    def _getDisabled(self, parsedObj):
        if parsedObj.inactive:
            return True
        else:
            return False
        
    def _getActionToDBEdit(self):
        if self.action == 'permit':
            return 'accept_action:accept'
        elif self.action == 'deny':
            return 'drop_action:drop'
        else:
            return ''
            
    def _getSrcToDBEdit(self, ruleID=0):
        if 'any' in [obj.name for obj in self.src]:
            return "addelement fw_policies ##{0} rule:{1}:src:'' globals:Any\n".format(self.policy, ruleID)
        elif self.src != None:
            ret = ''
            for src in self.src:
                ret += "addelement fw_policies ##{0} rule:{1}:src:'' network_objects:{2}\n".format(self.policy, ruleID, src.name)
            return ret
        else:
            return ''
            
    def _getDstToDBEdit(self, ruleID=0):
        if 'any' in [obj.name for obj in self.dst]:
            return "addelement fw_policies ##{0} rule:{1}:dst:'' globals:Any\n".format(self.policy, ruleID)
        elif self.dst != None:
            ret = ''
            for dst in self.dst:
                ret += "addelement fw_policies ##{0} rule:{1}:dst:'' network_objects:{2}\n".format(self.policy, ruleID, dst.name)
            return ret
        else:
            return ''
            
    def _getPortToDBEdit(self, ruleID=0):
        if 'any' in [obj.name for obj in self.port] or self.port == None:
            return "addelement fw_policies ##{0} rule:{1}:services:'' globals:Any\n".format(self.policy, ruleID)
        elif self.port != None:
            ret = ''
            for port in self.port:
                ret += "addelement fw_policies ##{0} rule:{1}:services:'' services:{2}\n".format(self.policy, ruleID, port.name)
            return ret
        else:
            return ''
            
    def _getTimeToDBEdit(self):
        return 'globals:Any'
        
    def _getTracksToDBEdit(self):
        if self.tracks:
            return 'tracks:Log'
        else:
            return 'tracks:None'
            
    def _getInstallOnToDBEdit(self):
        if self.installOn != None and self.installOn != '':
            return 'network_objects:'+self.installOn
        else:
            return 'globals:Any'
        
    def _getDisabledToDBEdit(self):
        if self.disabled:
            return 'true'
        else:
            return 'false'
    
    def _getSrcToString(self):
        return ';'.join([obj.name for obj in self.src])
        
    def _getDstToString(self):
        return ';'.join([obj.name for obj in self.dst])
        
    def _getPortToString(self):
        return ';'.join([obj.name for obj in self.port])
        
    def mergeWith(self, aclToMerge):
        for src in aclToMerge.src:
            if not src in self.src:
                self.src.append(src)
        for dst in aclToMerge.dst:
            if not dst in self.dst:
                self.dst.append(dst)
        for port in aclToMerge.port:
            if not port in self.port:
                self.port.append(port)
        
        self.desc = self.getDesc()
        if aclToMerge.getDesc() != '' and self.desc != aclToMerge.getDesc():
            self.desc += ';'+aclToMerge.getDesc()
        for line in aclToMerge.ciscoLines:
            self.addCiscoLine(line)
            
    def toString(self, indent='', verify=False, inclChild=True):
        ret = ''
        if not isarray(self.src):
            srcName = self.src.name
        else:
            srcName = self._getSrcToString()
        if not isarray(self.dst):
            dstName = self.dst.name
        else:
            dstName = self._getDstToString()
        if not isarray(self.port):
            portName = self.port.name
        else:
            portName = self._getPortToString()

        ret += indent+"ACLRule(name=%s,src=%s,dst=%s,port=%s,action=%s,"\
                      "pol=%s,inst=%s,disabled=%s,desc=%s)" % \
                (self.name,srcName,dstName,portName,self.action,self.policy,\
                 self.installOn,str(self.disabled),self.getDesc())
        if inclChild:
            ret += "\n"
            ret += indent+" Desc:"+self.getDesc()+"\n"
            for src in self.src:
                ret += indent+" Src:"+src.toString(' ')
            for dst in self.dst:
                ret += indent+" Dst:"+dst.toString(' ')
            for port in self.port:
                ret += indent+" Port:"+port.toString(' ')
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEditLegacy(self):
        global ACL_RULE_INDEX
        ACL_RULE_INDEX = ACL_RULE_INDEX + 1
        ret = '# Creating new rule: {0}\n'\
                'modify fw_policies ##{1} rule:{11}:name "{0}"\n'\
                'modify fw_policies ##{1} rule:{11}:comments "{2}"\n'\
                'modify fw_policies ##{1} rule:{11}:disabled {10}\n'\
                'rmbyindex fw_policies ##{1} rule:{11}:track 0\n'\
                'addelement fw_policies ##{1} rule:{11}:track {3}\n'\
                'addelement fw_policies ##{1} rule:{11}:time {4}\n'\
                'addelement fw_policies ##{1} rule:{11}:install:\'\' {5}\n'\
                'rmbyindex fw_policies ##{1} rule:{11}:action 0\n'\
                'addelement fw_policies ##{1} rule:{11}:action {6}\n'\
                '{7} modify fw_policies ##{1} rule:{11}:src:op\n'\
                '{8} modify fw_policies ##{1} rule:{11}:dst:op\n'\
                '{9} modify fw_policies ##{1} rule:{11}:services:op\n'\
                .format(self.name, \
                        self.policy, \
                        self.getDesc(), \
                        self._getTracksToDBEdit(), \
                        self._getTimeToDBEdit(), \
                        self._getInstallOnToDBEdit(), \
                        self._getActionToDBEdit(), \
                        self._getSrcToDBEdit(ACL_RULE_INDEX), \
                        self._getDstToDBEdit(ACL_RULE_INDEX), \
                        self._getPortToDBEdit(ACL_RULE_INDEX), \
                        self._getDisabledToDBEdit(), \
                        ACL_RULE_INDEX)    
        return ret

    def toDBEdit(self):
        global ACL_RULE_INDEX
        ret = '# Creating new rule: {0}\n'\
                'addelement fw_policies ##{1} rule security_rule\n'\
                'modify fw_policies ##{1} rule:{11}:name "{0}"\n'\
                'modify fw_policies ##{1} rule:{11}:comments "{2}"\n'\
                'modify fw_policies ##{1} rule:{11}:disabled {10}\n'\
                'modify fw_policies ##{1} rule:{11}:src rule_source\n'\
                'modify fw_policies ##{1} rule:{11}:dst rule_destination\n'\
                'modify fw_policies ##{1} rule:{11}:services rule_services\n'\
                'modify fw_policies ##{1} rule:{11}:install rule_install\n'\
                '{7}modify fw_policies ##{1} rule:{11}:src:op \'\'\n'\
                '{8}modify fw_policies ##{1} rule:{11}:dst:op \'\'\n'\
                '{9}modify fw_policies ##{1} rule:{11}:services:op \'\'\n'\
                'addelement fw_policies ##{1} rule:{11}:action {6}\n'\
                'addelement fw_policies ##{1} rule:{11}:install:\'\' {5}\n'\
                'rmbyindex fw_policies ##{1} rule:{11}:track 0\n'\
                'addelement fw_policies ##{1} rule:{11}:track {3}\n'\
                'addelement fw_policies ##{1} rule:{11}:time {4}\n'\
                .format(self.name, \
                        self.policy, \
                        self.getDesc(), \
                        self._getTracksToDBEdit(), \
                        self._getTimeToDBEdit(), \
                        self._getInstallOnToDBEdit(), \
                        self._getActionToDBEdit(), \
                        self._getSrcToDBEdit(ACL_RULE_INDEX), \
                        self._getDstToDBEdit(ACL_RULE_INDEX), \
                        self._getPortToDBEdit(ACL_RULE_INDEX), \
                        self._getDisabledToDBEdit(), \
                        ACL_RULE_INDEX)    
        ACL_RULE_INDEX = ACL_RULE_INDEX + 1
        return ret

class CiscoParser():
    configFile = None
    parse = None
    
    def __init__(self):
        pass
    
    def parse(self,configFile,syntax):
        self.configFile = configFile
        self.parse = CiscoConfParse(configFile,factory=True,syntax=syntax)
                    
    def getAllObjs(self):
        return self.getNameObjs() + \
                self.getHostObjs() + \
                self.getNetObjs() + \
                self.getRangeObjs() + \
                self.getPortObjs()
                
    def getAllGroups(self):
        return    self.getNetGroups() + \
                self.getPortGroups()
                
    def getNameObjs(self):
        return [obj for obj in self.parse.find_objects("^name\s")]
        
    def getHostObjs(self):
        return [obj for obj in self.parse.find_objects(r"^object\snetwork") \
                    if obj.re_search_children(r"^\shost")]

    def getNetObjs(self):
        return [obj for obj in self.parse.find_objects(r"^object\snetwork") \
                    if obj.re_search_children(r"^\ssubnet")]

    def getRangeObjs(self):
        return [obj for obj in self.parse.find_objects(r"^object\snetwork") \
                    if obj.re_search_children(r"^\srange")]

    def getSinglePortObjs(self):
        return [obj for obj in self.parse.find_objects(r"^object\sservice") \
                    if obj.re_search_children(r"^\sservice\s\w+\s\w+\seq")]

    def getPortRangeObjs(self):
        return [obj for obj in self.parse.find_objects(r"^object\sservice") \
                    if obj.re_search_children(r"^\sservice\s\w+\s\w+\srange")]
                    
    def getNetGroups(self):
        return [obj for obj in self.parse.find_objects(r"^object-group\snetwork")]
                    
    def getPortGroups(self):
        return [obj for obj in self.parse.find_objects(r"^object-group\sservice")] + \
                [obj for obj in self.parse.find_objects(r"^object-group\sicmp-type")]
                    
    def getProtoGroups(self):
        return [obj for obj in self.parse.find_objects(r"^object-group\sprotocol")]
                
    def getNatRules(self):
        return [obj for obj in self.parse.find_objects(r"^object\snetwork") \
                    if obj.re_search_children(r"^\snat")]    
                    
    def getBasicACLRules(self):
        return self.parse.find_objects(r"^access-list\s\d+\s(permit|deny)")
    
    def getACLRules(self):
        return self.parse.find_objects(r"^access-list\s\w+")
    
    def getIPACLRules(self):
        return self.parse.find_objects(r"^ip\saccess-list")
    
class Cisco2Checkpoint(CiscoObject):

    obj_list = []
    importSrc = None        # like configFile 
    configFile = None
    parser = None
    syntax = None
    policy = None
    installOn = None
    natInstallOn = None
    disableRules = None
    forceLog = None
    flattenInlineNetGroups = None
    flattenInlineSvcGroups = None
    
    nameImCt = 0
    nameCt = 0
    hostCpCt = 0        # from checkpoint xml
    hostImCt = 0        # from cisco file
    hostCrCt = 0        # dynamically created
    hostCt = 0          # after merge/cleanup
    netCpCt = 0
    netImCt = 0
    netCrCt = 0
    netCt = 0
    rangeCpCt = 0
    rangeImCt = 0
    rangeCrCt = 0
    rangeCt = 0
    singlePortCpCt = 0
    singlePortImCt = 0
    singlePortCrCt = 0
    portRangeCpCt = 0
    portRangeImCt = 0
    portRangeCrCt = 0
    netGrImCt = 0
    netGrCt = 0
    portGrCt = 0
    natRuCt = 0
    aclRuEsCt = 0
    aclRuSPCt = 0
    aclRuImCt = 0
    aclRuCt = 0

    debug = False
    
    def __init__(self):
        pass
        
    def importConfig(self,xmlPortsFile,xmlNetworkObjectsFile,configFile,loadACLRules=True):
        self.importSrc = configFile
        self.obj_list = []
        self.configFile = configFile
        self.parser = CiscoParser()
        self.parser.parse(configFile, self.syntax)
        print_msg('Importing all objects except groups.')
        self._importCheckpointNetworkObjects(xmlNetworkObjectsFile)
        self._importNames(self.parser.getNameObjs())
        self._importHosts(self.parser.getHostObjs())
        self._importNets(self.parser.getNetObjs())
        self._importRanges(self.parser.getRangeObjs())
        self._fixDuplicateNames()
        self._fixDuplicateIp()
        self._fixDuplicateSubnet()
        self._fixDuplicateRange()
        self._importCheckpointPorts(xmlPortsFile)
        self._importSinglePorts(self.parser.getSinglePortObjs())
        self._importPortRanges(self.parser.getPortRangeObjs())
        self._importNetGroups(self.parser.getNetGroups())    
        self._importPortGroups(self.parser.getPortGroups())
        self._importProtoGroups(self.parser.getProtoGroups())
        self._importNatRules(self.parser.getNatRules())
        if loadACLRules:
            if self.syntax == 'ios':
                self._importACLRules(self.parser.getACLRules())
            elif self.syntax == 'asa':
                self._importASAACLRules(self.parser.getACLRules())
            self._importIPACLRules(self.parser.getIPACLRules())
            self._fixACLRuleRedundancy()
            if self.disableRules:
                self._disableRules()
        
        self.netGrCt = len(self.findObjByType(['CiscoNetGroup']))    # Remove this 
        
        if self.flattenInlineNetGroups:
            self._flattenInlineNetGroups()
            #self._deleteInlineNetGroups()

        if self.flattenInlineSvcGroups:
            self._flattenInlineSvcGroups()
            #self._deleteInlineSvcGroups()
            
    def _importNames(self, names):
        print_msg('Importing all names.')
        self.nameImCt = 0
        for n in names:
            print_debug('  Importing: %s' % n)
            self.addObj(CiscoName(self, n, color=self.color))
            self.nameImCt += 1
        
    def _importHosts(self, hosts):
        print_msg('Importing all hosts.')
        self.hostImCt = 0
        for h in hosts:
            print_debug('  Importing: %s' % h)
            self.addObj(CiscoHost(self, h, color=self.color))
            self.hostImCt += 1

    def _importNets(self, networks):
        print_msg('Importing all networks.')
        self.netImCt = 0
        for n in networks:
            print_debug('  Importing: %s' % n)
            self.addObj(CiscoNet(self, n, color=self.color))
            self.netImCt += 1

    def _importRanges(self, ranges):
        print_msg('Importing all ranges.')
        self.rangeImCt = 0
        for r in ranges:
            print_debug('  Importing: %r' % h)
            self.addObj(CiscoRange(self, r, color=self.color))
            self.rangeImCt += 1
            
    def _importSinglePorts(self, ports):
        print_msg('Importing all single ports objects.')
        self.singlePortImCt = 0
        for p in ports:                    
            print_debug('  Importing: %s' % p)
            self.addObj(CiscoServicePort(self, p))    
            self.singlePortImCt += 1
            
    def _importPortRanges(self, ports):
        print_msg('Importing all port ranges objects.')
        self.portRangeImCt = 0
        for p in ports:                    
            print_debug('  Importing: %s' % p)
            self.addObj(CiscoServiceRange(self, p))    
            self.portRangeImCt += 1
            
    def _importNetGroups(self, groups):
        print_msg('Importing all net/host/range groups.')
        self.netGrImCt = 0
        for newGrp in groups:                    
            print_debug('  Importing: %s' % newGrp)
            self.addObj(CiscoNetGroup(self, newGrp, color=self.color))    
            self.netGrImCt += 1
            
    def _importPortGroups(self, groups):
        print_msg('Importing all port groups.')
        self.portGrCt = 0
        for newGrp in groups:        
            print_debug('  Importing: %s' % newGrp)
            self.addObj(CiscoServiceGroup(self, newGrp))        
            self.portGrCt += 1
            
    def _importProtoGroups(self, groups):
        print_msg('Importing all protocol groups.')
        for newGrp in groups:        
            print_debug('  Importing: %s' % newGrp)
            obj = CiscoProtoGroup(self, newGrp)
            if 'any' in [member.name for member in obj.members]:
                self.addObj(member)
                self.portGrCt += 1
            
    def _importNatRules(self, rules):
        print_msg('Importing all NAT rules.')
        self.natRuCt = 0
        for r in rules:        
            self.addObj(CiscoNatRule(self, r, self.natInstallOn))    
            self.natRuCt += 1
            
    def _importACLRules(self, rules):
        print_msg('Importing all firewall rules. (access-list)')
        aclNames = []
        self.aclRuImCt = 0
        for acl in rules:
            self.addObj(CiscoACLRule(self, acl, '', \
                                     self.policy, self.installOn, \
                                     forceLog = self.forceLog))
            self.aclRuImCt += 1

    def _importASAACLRules(self, rules):
        print_msg('Importing all firewall rules. (access-list)')
        aclNames = []
        self.aclRuImCt = 0
        desc = None
        for acl in rules:
            if acl.type == 'remark':
                desc = acl.remark
            elif acl.type in ['extended','standard']:
                self.addObj(CiscoACLRule(self, acl, desc, \
                                         self.policy, self.installOn, \
                                         forceLog = self.forceLog))
                self.aclRuImCt += 1
                desc = None
            else:
                raise C2CException('Invalid ACL type. It should be '\
                                   'remark, extended or standard.' \
                                   'Value was: "%s"' % acl.type)
    
    def _importIPACLRules(self, rules):
        '''
        Conditions for not importing a rule:
            - Contain attribute "established"
            - Contain a source port
        '''
        print_msg('Importing all firewall rules. (ip access-list)')
        self.aclRuImCt = 0
        rem = None

        # for each "acl" (ip access-list *type* *name*)
        for acl in rules:
            # for each "child" (permit|deny|remark ...)
            for child in acl.children:
                if child.action == 'remark':
                    rem = child.remark
                elif child.action in ['permit','deny']:
                    if child.established:
                        print_msg('Rule with established keyword not imported: %s' % child.text)
                        self.aclRuEsCt += 1
                    elif child.src_port_method:
                        print_msg('Rule with source port not imported: %s' % child.text)
                        self.aclRuSPCt += 1
                    else:
                        self.addObj(CiscoACLRule(self, child, rem, \
                                                 self.policy, self.installOn, \
                                                 forceLog=self.forceLog))
                        self.aclRuImCt += 1
                else:
                    raise C2CException('Invalid ip access-list "%s"' % \
                                       child.text)
            rem = None

    def _disableRules(self):
        for aclRule in [obj for obj in self.obj_list \
                if isinstance(obj, CiscoACLRule)]:
            aclRule.disabled = True

    def _importCheckpointPorts(self, xmlPortsFile):
        print_msg('Importing Checkpoint ports objects')
        tree = et.parse(xmlPortsFile)
        for dict_el in tree.iterfind('services_object'):
            p = dict_el.find('port')
            t = dict_el.find('type')
            c = dict_el.find('comments')
            name,port,proto,comments = None,'','',''
            
            if dict_el.text != None: name = dict_el.text.rstrip()
            if p != None: port = p.text.rstrip()
            if t != None: proto = t.text.lower().rstrip()
            if c != None: comments = c.text
            
            if not (name in EXCLUDE_PORTS):
                if port != '' and port.isdigit() and proto in SUPPORTED_PROTO:
                    if port[0] == '>':
                        self.addObj(CiscoServiceRange(self, None, name, proto, first, '65535', comments, True))
                        self.portRangeCpCt += 1
                    elif port[0] == '<':
                        self.addObj(CiscoServiceRange(self, None, name, proto, '0', port, comments, True))
                        self.portRangeCpCt += 1
                    elif '-' in port:
                        first,last = port.split('-',1)
                        self.addObj(CiscoServiceRange(self, None, name, proto, first, last, comments, True))
                        self.portRangeCpCt += 1
                    else:
                        self.addObj(CiscoServicePort(self, None, name, proto, port, comments, True))    
                        self.singlePortCpCt += 1
                elif port == '' and proto == 'icmp':
                    self.addObj(CiscoIcmp(self, name, comments, True))
                
        self._addIcmpAlias()
        
    def _importCheckpointNetworkObjects(self, xmlNetworkObjectsFile):
        print_msg('Importing Checkpoint network objects')
        tree = et.parse(xmlNetworkObjectsFile)
        for dict_el in tree.iterfind('network_objects_object'):
            t = dict_el.find('type')
            c = dict_el.find('comments')
            name,type,comments = None,'',''
            
            if dict_el.text != None: name = dict_el.text.rstrip()
            if t != None: type = t.text.rstrip()
            if c != None and c.text != None: comments = c.text.lower().rstrip()
            
            if type == 'host':
                i = dict_el.find('ipaddr')
                if i != None: ipAddr = i.text.rstrip()
                self.addObj(CiscoHost(self, None, name, ipAddr, comments, True))
                self.hostCpCt += 1
            elif type == 'network':
                i = dict_el.find('ipaddr')
                n = dict_el.find('netmask')
                if i != None: ipAddr = i.text.rstrip()
                if n != None: netMask = n.text.rstrip()
                self.addObj(CiscoNet(self, None, name, ipAddr, netMask, comments, True))
                self.netCpCt += 1
            elif type == 'machine_range':
                f = dict_el.find('ipaddr_first')
                l = dict_el.find('ipaddr_last')
                if f != None: first = f.text.rstrip()
                if l != None: last = l.text.rstrip()
                self.addObj(CiscoRange(self, None, name, first, last, comments, True))
                self.rangeCpCt += 1
                
    def _addIcmpAlias(self):
        # Translate cisco value => checkpoint value
        print_msg('Adding ICMP Aliases')
        for icmpObj in [obj for obj in self.obj_list if isinstance(obj, CiscoIcmp)]:
            for i, j in ICMP_DIC.iteritems():
                if icmpObj.name == j:
                    #print_debug('Adding "%s" alias to "%s"' % (i,j))
                    icmpObj.addAlias(i)
        
    def _fixDuplicateNames(self):
        print_msg('Fixing duplicate names')
        for obj in self.obj_list:
            if obj.getClass() in NETOBJ_NAMED_CLASSES:
                foundList = self.findObjByName(obj.name)
                self._fixDuplicate(foundList, obj.name, obj.getClass())
        self.nameCt = len(self.findNewObjByType(['CiscoName']))
        self.hostCt = len(self.findNewObjByType(['CiscoHost']))

    def _fixDuplicateIp(self):
        print_msg('Fixing duplicate IP addresses')
        for obj in self.obj_list:
            if isinstance(obj, (CiscoHost)):
                foundList = self.findHostByAddr(obj.ipAddr)
                self._fixDuplicate(foundList, obj.ipAddr, obj.getClass())
        self.nameCt = len(self.findNewObjByType(['CiscoName']))
        self.hostCt = len(self.findNewObjByType(['CiscoHost']))
                        
    def _fixDuplicateSubnet(self):
        print_msg('Fixing duplicate subnets')
        for obj in self.obj_list:
            if isinstance(obj,CiscoNet):
                foundList = self.findNetByAddr(obj.ipAddr, obj.mask)
                self._fixDuplicate(foundList, obj.ipAddr+'/'+obj.mask, obj.getClass())
        self.netCt = len(self.findNewObjByType(['CiscoNet']))

    def _fixDuplicateRange(self):
        print_msg('Fixing duplicate ranges')
        for obj in self.obj_list:
            if isinstance(obj,CiscoRange):
                foundList = self.findRangeByAddr(obj.first, obj.last)
                self._fixDuplicate(foundList, obj.first+'-'+obj.last, obj.getClass())
        self.rangeCt = len(self.findNewObjByType(['CiscoRange']))
        
    def _fixDuplicate(self, foundList, objName, objType):
        if len(foundList) != 1:
            print_debug('  Object %s (%s) was found %i times. Deleting duplicates.' % (objName,objType,len(foundList)))
            print_debug('    Keeping: %s (%s)' % (foundList[0].name,foundList[0].getClass()))
            for objToDel in foundList[1:]:
                self._cleanObj(foundList[0], objToDel)

    def _fixACLRuleRedundancy(self):
        print_msg('Merging redundant ACL rules')
        aclRules = [obj for obj in self.obj_list \
                     if isinstance(obj, CiscoACLRule)]
        
        for i in range(0,len(aclRules)-2):
            for j in range(i+1,len(aclRules)-2):
                if self._areMergable(aclRules[i], aclRules[j]):
                    self._mergeRules(aclRules[i], aclRules[j])
                    if aclRules[j] in self.obj_list:
                        self.removeObj(aclRules[j])
        self.aclRuCt = len(self.findNewObjByType(['CiscoACLRule']))
        
    def _areMergable(self, obj1, obj2):
        # Conditions for merges
        # 1- Same(src, dst, action, tracks, installOn, time, policy, name, disabled), Different(port)
        # 2- Same(src, port, action, tracks, installOn, time, policy, name, disabled), Different(dst)
        # 3- Same(dst, port, action, tracks, installOn, time, policy, name, disabled), Different(src)
        if (obj1.src == obj2.src and obj1.dst == obj2.dst and obj1.action == obj2.action \
            and obj1.tracks == obj2.tracks and obj1.installOn == obj2.installOn \
             and obj1.time == obj2.time and obj1.policy == obj2.policy \
             and obj1.name == obj2.name and obj1.disabled == obj2.disabled) \
             or \
           (obj1.src == obj2.src and obj1.port == obj2.port and obj1.action == obj2.action \
             and obj1.tracks == obj2.tracks and obj1.installOn == obj2.installOn \
             and obj1.time == obj2.time and obj1.policy == obj2.policy \
             and obj1.name == obj2.name and obj1.disabled == obj2.disabled) \
             or \
           (obj1.dst == obj2.dst and obj1.port == obj2.port and obj1.action == obj2.action \
             and obj1.tracks == obj2.tracks and obj1.installOn == obj2.installOn \
             and obj1.time == obj2.time and obj1.policy == obj2.policy \
             and obj1.name == obj2.name and obj1.disabled == obj2.disabled):
            return True
        else:
            return False
            
    def _mergeRules(self, obj1, obj2):
        # Merge in obj1. obj2 will be deleted.
        print_debug('Merging: %s' % obj1.toString('', False, False))
        print_debug('With:    %s' % obj2.toString('', False, False))
        obj1.mergeWith(obj2)
        print_debug('Result:  %s' % obj1.toString('', False, False))
    
    def _cleanObj(self, objToKeep, objToDel):
        objToKeep.addAlias(objToDel.name, '    ')
        for alias in objToDel.alias:
            objToKeep.addAlias(alias, '    ')
        for ciscoLine in objToDel.ciscoLines:
            objToKeep.addCiscoLine(ciscoLine, '    ')            
        print_debug('    Deleting object: %s (%s)' % (objToDel.name, objToDel.getClass()))
        self.removeObj(objToDel)
        
    def _flattenInlineNetGroups(self):
        print_msg('Flattening DM_INLINE_NETWORK groups')
        aclRules = [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoACLRule)]        
        for fwr in aclRules:    # For each firewall rules
            for obj in fwr.src:    # For each source objects of the firewall rule.
                if (isinstance(obj, CiscoNetGroup) \
                    and obj.name.startswith(DM_INLINE_NET_PREFIX)):
                    self._flattenACLRuleAttribute(fwr, fwr.src, obj)
                    
            for obj in fwr.dst:    # For each destination objects of the firewall rule.
                if (isinstance(obj, CiscoNetGroup) \
                    and obj.name.startswith(DM_INLINE_NET_PREFIX)):
                    self._flattenACLRuleAttribute(fwr, fwr.dst, obj)
        
    def _flattenInlineSvcGroups(self):
        print_msg('Flattening DM_INLINE_SERVICE groups')
        aclRules = [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoACLRule)]        
        for fwr in aclRules:    # For each firewall rules
            for obj in fwr.port:    # For each service objects of the firewall rule.
                if (isinstance(obj, CiscoServiceGroup) \
                    and (obj.name.startswith(DM_INLINE_SVC_PREFIX) or \
                        obj.name.startswith(DM_INLINE_TCP_PREFIX) or \
                        obj.name.startswith(DM_INLINE_UDP_PREFIX))):
                    self._flattenACLRuleAttribute(fwr, fwr.port, obj)
        
    def _flattenACLRuleAttribute(self,fwr,fwrattr,group):
        print_debug('    Flattening object %s on rule %s' % (group.name,fwr.name))
        # Add group's member to firewall attribute
        for m in group.members:
            fwrattr.append(m)
        # Remove group from firewall attribute
        fwrattr.remove(group)
        group.alreadyExist = True

    def _deleteInlineNetGroups(self):
        ct = 0
        for obj in self.obj_list:
            if isinstance(obj, CiscoNetGroup) \
               and obj.name.startswith(DM_INLINE_NET_PREFIX):
                ct+=1
                self.removeObj(obj)
        print_msg('Deleted %i Inline network groups.' % ct)

    def _deleteInlineSvcGroups(self):
        ct = 0
        for obj in self.obj_list:
            if isinstance(obj, CiscoServiceGroup) \
                and (obj.name.startswith(DM_INLINE_NET_PREFIX) or \
                    obj.name.startswith(DM_INLINE_TCP_PREFIX) or \
                     obj.name.startswith(DM_INLINE_UDP_PREFIX)):
                ct+=1
                self.removeObj(obj)
        print_msg('Deleted %i Inline network groups.' % ct)

    def findObjByType(self,types):
        return [obj for obj in self.obj_list if (obj.getClass() in types)]
        
    def findNewObjByType(self,types):
        return [obj for obj in self.obj_list if (obj.getClass() in types and obj.alreadyExist == False)]
        
    def findObjByNameType(self,name,types):
        return [obj for obj in self.obj_list if (obj.getClass() in types \
                    and (obj.name.lower() == name.lower() or name in obj.alias))]
        
    # This function does not return ports or port groups
    def findObjByName(self,name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in NETOBJ_NAMED_CLASSES \
                        and (obj.name.lower() == name.lower() or name in obj.alias))]
    
    def findNameByName(self,name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoName' \
                        and obj.name == name)]

    def findNameByAddr(self,ipAddr):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoName' \
                        and obj.ipAddr == ipAddr)]

    def findHostByAddr(self,ipAddr):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in HOST_CLASSES \
                        and obj.ipAddr == ipAddr)]
                        
    def findNetByAddr(self,ipAddr,mask):
        return [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoNet) \
                        and obj.ipAddr == ipAddr and obj.mask == mask]
                        
    def findRangeByAddr(self,first,last):
        return [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoRange) \
                        and obj.first == first and obj.last == last]
                        
    def findServiceByNum(self,proto,port):
        return [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoServicePort) \
                        and obj.proto == proto and obj.port == port]
    
    def findServiceByRange(self,proto,first,last):
        return [obj for obj in self.obj_list \
                    if isinstance(obj, CiscoServiceRange) \
                        and obj.proto == proto and obj.first == first and obj.last == last]
    
    def findServiceByName(self, name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in SVCOBJ_NAMED_CLASSES \
                        and obj.name.lower() == name.lower() or name in obj.alias)]
    
    def findIcmpByName(self, name):
        return [obj for obj in self.obj_list \
                    if (isinstance(obj, CiscoIcmp) or isinstance(obj, CiscoAnyIcmp)) \
                        and (obj.name.lower() == name.lower() or name in obj.alias)]
                        
    def findRuleByDesc(self, desc):
        return [obj for obj in self.obj_list \
                if (isinstance(obj, CiscoACLRule) and obj.desc == desc)]
                
    def findDuplicateNetGroup(self, obj2):
        return [obj1 for obj1 in self.obj_list 
                if isinstance(obj1,CiscoNetGroup) and obj1 == obj2]
                
    def addObj(self,obj):
        if obj == None:
            raise C2CException('Cannot add a None object to c2c.')
        self.obj_list.append(obj)
        
    def removeObj(self,obj):
        self.obj_list.remove(obj)
        
    def setPolicy(self, policy):
        self.policy = policy
        
    def setInstallOn(self, installOn):
        self.installOn = installOn

    def setNatInstallOn(self, natInstallOn):
        self.natInstallOn = natInstallOn
        
    def setDisableRules(self, disableRules):
        self.disableRules = disableRules
        
    def setForceLog(self, forceLog):
        self.forceLog = forceLog
        
    def setDebug(self, debug):
        self.debug = debug
        if debug:
            global C2C_DEBUG
            C2C_DEBUG = True
    
    def setSyntax(self, syntax):
        self.syntax = syntax

    def setACLRuleIndex(self, index):
        global ACL_RULE_INDEX
        ACL_RULE_INDEX = index
        
    def setFlattenInlineNetGroups(self, flattenInlineNetGroups):
        self.flattenInlineNetGroups = flattenInlineNetGroups
        
    def setFlattenInlineSvcGroups(self, flattenInlineSvcGroups):
        self.flattenInlineSvcGroups = flattenInlineSvcGroups
        
    def getAllObjs(self, verify=False):
        return ''.join([obj.toString('', verify) for obj in self.obj_list if obj.alreadyExist == False])
        
    def getAllHosts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoHost) or isinstance(obj, CiscoName))])
            
    def getAllPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if isinstance(obj, (CiscoServicePort,CiscoServiceRange))])

    def getAllNonNumPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoServicePort) and (not obj.port.isdigit()))])
        
    def getAllPortGroups(self):
        return ''.join([obj.toString() for obj in self.obj_list if isinstance(obj, CiscoServiceGroup)])

    def getAlreadyExistPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoServicePort) and obj.alreadyExist == True)] + \
                    [obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoServiceRange) and obj.alreadyExist == True )])

    def getNewPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoServicePort) and obj.alreadyExist == False)] + \
                    [obj.toString() for obj in self.obj_list if (isinstance(obj, CiscoServiceRange) and obj.alreadyExist == False )])
                    
    def getAllIcmp(self):
        return ''.join([obj.toString() for obj in self.obj_list if isinstance(obj, CiscoIcmp)])

    def getNatRules(self):
        return ''.join([obj.toString() for obj in self.obj_list if isinstance(obj, CiscoNatRule)])    
        
    def getACLRules(self):
        return ''.join([obj.toString() for obj in self.obj_list if isinstance(obj, CiscoACLRule)])                        
                        
    def getSummary(self):
        return '# Summary of the findings in "{0}"\n'\
            '#\n'\
            '# Number of names (before merge/cleanup): {1}\n'\
            '# Number of names (after merge/cleanup): {2}\n'\
            '# Number of hosts (imported from cisco file): {3}\n'\
            '# Number of hosts (imported from checkpoint xml): {4}\n'\
            '# Number of hosts (dynamically created): {5}\n'\
            '# Number of hosts (after merge/cleanup): {6}\n'\
            '# Number of subnet (imported from cisco file): {7}\n'\
            '# Number of subnet (imported from checkpoint xml): {8}\n'\
            '# Number of subnet (dynamically created): {9}\n'\
            '# Number of subnet (after merge/cleanup): {10}\n'\
            '# Number of range (imported from cisco file): {11}\n'\
            '# Number of range (imported from checkpoint xml): {12}\n'\
            '# Number of range (dynamically created): {13}\n'\
            '# Number of range (after merge/cleanup): {14}\n'\
            '# Number of subnet groups: {15}\n'\
            '# Number of service groups: {16}\n'\
            '# Number of nat rules: {17}\n'\
            '# Number of acl rules (not imported: established): {18}\n'\
            '# Number of acl rules (not imported: source port): {19}\n'\
            '# Number of acl rules (before merge/cleanup): {20}\n'\
            '# Number of acl rules (after merge/cleanup): {21}\n'\
            '# Number of single ports (imported from cisco file): {22}\n'\
            '# Number of single ports (imported from checkpoint xml): {23}\n'\
            '# Number of single ports (dynamically created): {24}\n'\
            '# Number of port range (imported from cisco file): {25}\n'\
            '# Number of port range (imported from checkpoint xml): {26}\n'\
            '# Number of port range (dynamically created): {27}\n'\
            .format(self.importSrc, \
                        self.nameImCt, \
                        self.nameCt, \
                        self.hostCpCt, \
                        self.hostImCt, \
                        self.hostCrCt, \
                        self.hostCt, \
                        self.netCpCt, \
                        self.netImCt, \
                        self.netCrCt, \
                        self.netCt, \
                        self.rangeCpCt, \
                        self.rangeImCt, \
                        self.rangeCrCt, \
                        self.rangeCt, \
                        self.netGrCt, \
                        self.portGrCt, \
                        self.natRuCt, \
                        self.aclRuEsCt, \
                        self.aclRuSPCt, \
                        self.aclRuImCt, \
                        self.aclRuCt, \
                        self.singlePortCpCt, \
                        self.singlePortImCt, \
                        self.singlePortCrCt, \
                        self.portRangeCpCt, \
                        self.portRangeImCt, \
                        self.portRangeCrCt)
    
    def toDBEdit(self):
        return ''.join([obj.toDBEdit() for obj in self.obj_list if isinstance(obj, CiscoName) and obj.alreadyExist == False] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoHost) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoNet) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoRange) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoNetGroup) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoServicePort) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoServiceRange) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (isinstance(obj, CiscoServiceGroup) and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if isinstance(obj, CiscoNatRule) and obj.type in ['static','hide']] + \
                [obj.toDBEdit() for obj in self.obj_list if isinstance(obj, CiscoACLRule)]) + \
                "update_all"
        #["# Enable global properties NAT ip pool\n"] + \
        #["modify properties firewall_properties enable_ip_pool true\n"] + \

class Cisco2CheckpointManager(Cisco2Checkpoint):
        
    c2c_list = []
    cpPortsFile = None
    configDir = None
        
    def __init__(self):
        self.obj_list = []
        self.c2c_list = []
        
    def importConfig(self, cpPortsFile, cpNetObjFile, configDir):
        self.cpPortsFile = cpPortsFile
        self.importSrc = configDir
        self.configDir = configDir
        
        fileList = os.listdir(configDir)
        for f in fileList:
            filePath = configDir + '\\' + f
            if os.path.isfile(filePath) and CONFIG_FILE_SUFFIX in filePath:
                print_msg('Opening "%s"' % filePath)
                newC2c = Cisco2Checkpoint()
                newC2c.setDebug(self.debug)
                newC2c.setPolicy(self.policy)
                newC2c.setInstallOn(self.installOn)
                newC2c.setNatInstallOn(self.natInstallOn)
                newC2c.importConfig(cpPortsFile,cpNetObjFile,filePath,False)
                self.c2c_list.append(newC2c)
            else:
                print_debug('Invalid file: %s' % filePath)
            
        self._renameDuplicateGroups()
        self._importAllSimpleObjects()
        self._fixDuplicatePorts()
        self._updateReferer()
        #self._fixDuplicateNames()
        self._fixDuplicateIp()
        self._fixDuplicateSubnet()
        self._fixDuplicateRange()
        self._fixDuplicateAny()
        self._importAllNetGroups()
        self._importAllNatRules()
        self._importAllACLRules()
        self.aclRuImCt = len(self.findObjByType(['CiscoACLRule']))
        self._fixACLRuleRedundancy()
        
        if self.flattenInlineNetGroups:
            self._flattenInlineNetGroups()

        if self.flattenInlineSvcGroups:
            self._flattenInlineSvcGroups()
            
        self._updateCounters()
    
    def _renameDuplicateGroups(self):
        print_msg('['+self.getClass()+'] Renaming duplicate network groups')
        for c2c in self.c2c_list:
            for grpObj in [obj for obj in c2c.obj_list if obj.getClass() in GROUP_CLASSES]:
                # if group is in other c2c instances
                dupGrpList = [obj for obj in flatten_array([tmpc2c.obj_list for tmpc2c in self.c2c_list]) if obj.getClass() in GROUP_CLASSES and (grpObj.name == obj.name or grpObj.name in obj.alias)]
                if len(dupGrpList) > 0:
                    self._renameObjects(dupGrpList, grpObj.name)
        
    def _renameObjects(self, foundList, grpName):
        if len(foundList) != 1:
            print_debug('  Object %s (%s) was found %i times in different config files. Renaming duplicates.' % (foundList[0].name,foundList[0].getClass(),len(foundList)))
            print_debug('    Keeping: %s (%s)' % (foundList[0].name,foundList[0].c2c.configFile))
            num = 1
            for objToRename in foundList[1:]:
                oldName = objToRename.name
                objToRename.name = objToRename.name+('-%02d' % num)
                print_debug('    Renaming %s (%s) to %s' % (oldName,objToRename.c2c.configFile,objToRename.name))
                num += 1
                
    def _importAllSimpleObjects(self):
        print_msg('['+self.getClass()+'] Importing objects except net groups and ACL rules')
        for c2c in self.c2c_list:
            self.obj_list += [obj for obj in c2c.obj_list 
                               if isinstance(obj, (CiscoACLRule, CiscoNetGroup, 
                                                   CiscoNatRule))]
            
    def _importAllNetGroups(self):
        print_msg('['+self.getClass()+'] Importing groups')
        for c2c in self.c2c_list:
            self._importNetGroups(c2c.parser.getNetGroups())
            
    def _importAllNatRules(self):
        print_msg('['+self.getClass()+'] Importing NAT rules')
        for c2c in self.c2c_list:
            self._importNatRules(c2c.parser.getNatRules())
            
    def _importAllACLRules(self):
        print_msg('['+self.getClass()+'] Importing ACL rules')
        for c2c in self.c2c_list:
            self._importACLRules(c2c.parser.getACLRules())

    def _updateReferer(self):
        print_msg('['+self.getClass()+'] Updating referer variable "c2c"')
        for obj in self.obj_list:
            obj.c2c = self
            
    def _fixDuplicateAny(self):
        print_msg('['+self.getClass()+'] Fixing duplicate any objects')
        for obj in self.obj_list:
            if obj.getClass() in ANY_CLASSES:
                foundList = self.findObjByType(obj.getClass())
                self._fixDuplicate(foundList, obj.name, obj.getClass())
            
    def _fixDuplicatePorts(self):
        print_msg('['+self.getClass()+'] Fixing duplicate ports')
        for obj in self.obj_list:
            if isinstance(obj, CiscoServicePort):
                foundList = self.findServiceByNum(obj.proto, obj.port)
                self._fixDuplicate(foundList, obj.name, obj.getClass())
                
    # TODO: Should check obj_list instead of c2c_list
    def _updateCounters(self):
        print_msg('['+self.getClass()+'] Updating counters')
        self.nameImCt = sum([obj.nameImCt for obj in self.c2c_list])
        self.nameCt = sum([obj.nameCt for obj in self.c2c_list])
        self.hostImCt = sum([obj.hostImCt for obj in self.c2c_list])
        self.hostCt = sum([obj.hostCt for obj in self.c2c_list])
        self.netImCt = sum([obj.netImCt for obj in self.c2c_list])
        self.netCt = sum([obj.netCt for obj in self.c2c_list])
        self.rangeImCt = sum([obj.rangeImCt for obj in self.c2c_list])
        self.rangeCt = sum([obj.rangeCt for obj in self.c2c_list])
        self.netGrImCt = sum([obj.netGrImCt for obj in self.c2c_list])
        self.netGrCt = sum([obj.netGrCt for obj in self.c2c_list])
        self.portGrCt = sum([obj.portGrCt for obj in self.c2c_list])
        self.natRuCt = sum([obj.natRuCt for obj in self.c2c_list])
        #self.aclRuImCt = sum([obj.aclRuImCt for obj in self.c2c_list])
        self.aclRuCt = len(self.findObjByType(['CiscoACLRule']))

