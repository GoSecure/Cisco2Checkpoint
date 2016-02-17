from ciscoconfparse import CiscoConfParse
from config import *
from pprint import pprint
import xml.etree.ElementTree as et
import copy
import socket
import os
import re

def isarray(var):
    return isinstance(var, (list, tuple))
    
def isipaddress(var):
    try:
        socket.inet_aton(var)
        return True
    except socket.error:
        return False

def get_net_size(netmask):
    binary_str = ''
    for octet in netmask.split('.'):
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip('0')))
        
def make_flat(l):
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
    
class C2CException(Exception):
    pass
    
class CiscoObject():
    """A name command"""
    name = None
    desc = None
    color = None
    alias = []            # Alias name used to keep associations when objects
                        # are merged from IP addresses.
    dbClass = None        # Used to determine checkpoint class    
                        # Ex: 
    alreadyExist = False        # Flag to determine if it already exist in checkpoint database
    c2c = None            # Reference to c2c object (parent) 
    ciscoLines = []    # Cisco line that was used to import the object (useful for verify)
    
    def __init__(self, c2c, ciscoLine, name, desc='', alreadyExist=False, \
                color=None):
        n = copy.deepcopy(name)
        self.name = self._sanitizeIllegalWords(self._sanitizeName(name))
        self.ciscoLines = []
        self.ciscoLines.append(ciscoLine)
        self.desc = desc
        self.c2c = c2c
        self.alias = []
        self.addAlias(n)
        self.alreadyExist = alreadyExist
        self.color = color
        
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
            if self.getClass() == 'CiscoNet':
                return NEW_NET_PREFIX+name
            elif self.getClass() == 'CiscoRange':
                return NEW_RANGE_PREFIX+name
            elif self.getClass() == 'CiscoName' or self.getClass() == 'CiscoHost':
                return NEW_HOST_PREFIX+name
            elif self.getClass() == 'CiscoPortGroup' or self.getClass() == 'CiscoNetGroup':
                return NEW_GROUP_PREFIX+name
            elif self.getClass() in ['CiscoSinglePort','CiscoPortRange'] and self.proto == 'tcp':
                return TCP_PREFIX+name
            elif self.getClass() in ['CiscoSinglePort','CiscoPortRange'] and self.proto == 'udp':
                return UDP_PREFIX+name
            elif self.getClass() in ['CiscoSinglePort','CiscoPortRange'] and self.proto == 'tcp-udp':
                return TCPUDP_PREFIX+name
            else:
                return name
        else:
            return name
            
    def getClass(self):
        return self.__class__.__name__
        
    def getDesc(self):
        if self.desc == None:
            return ''
        else:
            return str(self.desc.replace('"\/ ', '').replace(' \/"', ''))
            
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
            if C2C_DEBUG: print(WARN_PREFIX+indent+'Adding Alias "%s" on object "%s"' % (text, str(self.name)))
            self.alias.append(text)
    
    def addCiscoLine(self,text,indent=''):
        if text != None and not text in self.ciscoLines:
            #if C2C_DEBUG: print(WARN_PREFIX+indent+'Adding CiscoLine "%s" on object "%s"' % (text, str(self.name)))
            self.ciscoLines.append(text)

    def setColor(self, color):
        self.color = color
        
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+'(name=%s,desc=%s)' % (self.name,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret
        
    def toDBEdit(self):
        return ''    
        
    def toDBEditElement(self, groupName):
        return ''
        
class CiscoPort(CiscoObject):
    """A cisco port"""
    proto = None
    
    def __init__(self, c2c, name, alreadyExist=False):
        CiscoObject.__init__(self, c2c, None, name)
        self.alreadyExist = alreadyExist
        
    def _toDBEditType(self):
        if self.proto == 'tcp':
            return 'tcp_service'
        elif self.proto == 'udp':
            return 'udp_service'
        elif self.proto == 'any':
            return ''
        else:
            print(self.name)
            print(self.port)
            print(self.getClass())
            raise C2CException('Protocol not supported: %s' % self.proto)
            
    def _convertPort(self, text):
        for i, j in PORT_DIC.iteritems():
            #text = text.replace(i, j)
            text = re.sub(r'^'+i+'$', j, text)
        return text.rstrip()
        
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoGroup(CiscoObject):                
    members = []
    
    def __init__(self, c2c, ciscoLine, name, members=None, desc=None, \
                 alreadyExist=False, color=None):
        self.members = []
        CiscoObject.__init__(self, c2c, ciscoLine, name, desc, alreadyExist, \
                            color)
        if members != None:
            self.members = members
        
    def _convertProto(self, text):
        if text != None:
            for i, j in PROTO_DIC.iteritems():
                text = re.sub(r'^'+i+'$', j, text)
            return text.rstrip().lower()

    def _convertPort(self, text):
        for i, j in PORT_DIC.iteritems():
            text = re.sub(r'^'+i+'$', j, text)
        return text.rstrip()

    def hostmask2netmask(self,hostmask):
        mask_bytes = hostmask.split('.',3)
        mask_bytes = [str(int(b) ^ 255) for b in mask_bytes]
        return '.'.join(mask_bytes)
        
    def _getMemberObj(self, type, v1, v2=None, v3=None):
        if type == 'host' and v1 == 'any':
            name = v1
            obj_list = self.c2c.findObjByName(name)
        elif type in ['port','ip','tcp','udp'] and v1 == 'any':
            name = v1
            #obj_list = self.c2c.findIPServiceByName(name)
            obj_list = self.c2c.findObjByNameType(name,'CiscoAnyPort')
        #elif type == 'object-group':
        #    name = v1
        #    obj_list = self.c2c.findServiceByName(name)
        elif type == 'icmp':
            name = v1
            obj_list = self.c2c.findIcmpByName(name)
        elif type == 'icmp-object':
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
        elif type == 'host-group':
            name = v1
            obj_list = self.c2c.findObjByName(name)
        elif type == 'port-group':
            name = v1
            obj_list = self.c2c.findServiceByName(name)
        elif type == 'port-object':
            name = v1
            obj_list = self.c2c.findServiceByName(name)
        elif type == 'eq':        # port-object eq X
            name,proto,port = v1+'/'+v2,v1,v2
            port = self._convertPort(port)
            if proto in ['tcp','udp']:
                obj_list = self.c2c.findServiceByNum(proto,port)
            elif proto == 'tcp-udp':
                obj_list1 = self.c2c.findServiceByNum('tcp',port)
                obj_list2 = self.c2c.findServiceByNum('udp',port)
                ret1 = self._parseResult(obj_list1, name, type)
                ret2 = self._parseResult(obj_list2, name, type)
                if ret1 and ret2:
                    return obj_list1 + obj_list2
                else:
                    return None                    
        elif type == 'range':        # port-object range X Y
            name,proto,first,last = v1+'/'+v2+'-'+v3,v1,v2,v3
            if proto in ['tcp','udp']:
                obj_list = self.c2c.findServiceByRange(proto,first,last)
            elif proto == 'tcp-udp':
                obj_list1 = self.c2c.findServiceByRange('tcp',first,last)
                obj_list2 = self.c2c.findServiceByRange('udp',first,last)
                ret1 = self._parseResult(obj_list1, name, type)
                ret2 = self._parseResult(obj_list2, name, type)
                if ret1 and ret2:
                    return obj_list1 + obj_list2
                else:
                    return None
        elif type in ['static', 'dynamic']:                # Nat rules
            name = v1
            obj_list = self.c2c.findObjByName(name)
        else:
            name,subnet,mask = type+'/'+v1,type,v1        # Yes this is ugly. Thx cisco.
            type = 'subnet-mask'
            obj_list = self.c2c.findNetByAddr(subnet,mask)
                        
        return self._parseResult(obj_list, name, type)

    def _parseResult(self,obj_list, name, type):
        if len(obj_list) == 1: 
            return obj_list[0]
        elif len(obj_list) > 1:
            if C2C_DEBUG: print(WARN_PREFIX+'Warning: Found %i instances of "%s" (%s)' % (len(obj_list),name,type))
            return obj_list[0]
        else:
            if C2C_DEBUG: print(WARN_PREFIX+'Warning: Could not find object "%s" (%s). The script will create it.' % (name,type))
            return None
            
    def _createMemberObj(self, type, v1, v2=None, v3=None):
        if type == 'host' and v1 == 'any':
            newObj = CiscoAnyHost(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'port' and v1 == 'any':
            newObj = CiscoAnyPort(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'ospf' and v1 == 'any':
            newObj = CiscoOspfProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'esp' and v1 == 'any':
            newObj = CiscoEspProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type in ['ah','ahp'] and v1 == 'any':
            newObj = CiscoAHProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'vrrp' and v1 == 'any':
            newObj = CiscoVrrpProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'skip' and v1 == 'any':
            newObj = CiscoSkipProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'gre' and v1 == 'any':
            newObj = CiscoGreProto(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'icmp' and v1 == 'any':
            newObj = CiscoAnyIcmp(self)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'icmp':
            name = v1
            newObj = CiscoIcmp(self, name)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'icmp-object':
            name = v1
            newObj = CiscoIcmp(self, name)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        elif type == 'host':
            newObj = CiscoHost(self, None, NEW_HOST_PREFIX+v1, v1, \
                               color=self.c2c.color)
            self.c2c.addObj(newObj)
            self.c2c.hostCrCt += 1
            self.members.append(newObj)
        elif type == 'subnet':
            subnet,mask = v1,v2
            netSize = get_net_size(mask)
            newObj = CiscoNet(self, None, NEW_NET_PREFIX+subnet+'-'+netSize, \
                         subnet, mask, color=self.c2c.color)
            self.c2c.addObj(newObj)
            self.c2c.netCrCt += 1
            self.members.append(newObj)
        elif type == 'object' or type == 'object-group':
            raise C2CException('Cannot create an object member "%s" on the fly.' % v1)
        elif type == 'host-group':
            raise C2CException('Cannot create a net group member "%s" on the fly.' % v1)
        elif type == 'port-group':
            raise C2CException('Cannot create a port group member "%s" on the fly.' % v1)
        elif type == 'eq':        # port-object eq X
            proto,port = v1,v2
            port = self._convertPort(port)
            if proto in ['tcp','udp']:
                newObj = CiscoSinglePort(self, None, None, proto, port)
                self.c2c.addObj(newObj)
                self.c2c.singlePortCrCt += 1
                self.members.append(newObj)
            elif proto == 'tcp-udp':
                name,proto,port = v1+'/'+v2,v1,v2
                obj_list1 = self.c2c.findServiceByNum('tcp',port)        # Redo the parsing because
                obj_list2 = self.c2c.findServiceByNum('udp',port)        # one of these could exist.
                ret1 = self._parseResult(obj_list1, name, 'tcp')
                ret2 = self._parseResult(obj_list2, name, 'udp')
                
                if ret1 == None:
                    newObj1 = CiscoSinglePort(self, None, None, 'tcp', port)
                    self.c2c.addObj(newObj1)
                    self.c2c.singlePortCrCt += 1
                    self.members.append(newObj1)
                if ret2 == None:
                    newObj2 = CiscoSinglePort(self, None, None, 'udp', port)
                    self.c2c.addObj(newObj2)
                    self.c2c.singlePortCrCt += 1
                    self.members.append(newObj2)

        elif type == 'range':        # port-object range X Y
            proto,first,last = v1,v2,v3
            if proto in ['tcp','udp']:            
                newObj = CiscoPortRange(self, None, None, proto, first, last)
                self.c2c.addObj(newObj)
                self.c2c.portRangeCrCt += 1
                self.members.append(newObj)
            elif proto == 'tcp-udp':
                newObj1 = CiscoPortRange(self, None, None, 'tcp', first, last)
                newObj2 = CiscoPortRange(self, None, None, 'udp', first, last)
                self.c2c.addObj(newObj1)
                self.c2c.portRangeCrCt += 1
                self.c2c.addObj(newObj2)
                self.c2c.portRangeCrCt += 1
                self.members.append(newObj1)
                self.members.append(newObj2)
        elif type in ['static', 'dynamic']:                # Nat rules
            name = v1
            newObj = CiscoHost(self, None, name, name, None, True, \
                               color=self.c2c.color)
            self.c2c.addObj(newObj)
            self.c2c.hostCrCt += 1
            #raise C2CException('Cannot create a nat external IP "%s" on the fly.' % name)
        elif isipaddress(type):
            subnet,mask = type,v1        # Yes this is ugly.
            newObj = CiscoNet(self, None, NEW_NET_PREFIX+subnet, subnet, mask)
            self.c2c.addObj(newObj)
            self.members.append(newObj)
        else:
            raise C2CException('Invalid type: %s' % type)

    def _getOrCreateMemberObj(self,type,v1,v2=None,v3=None):
        obj = self._getMemberObj(type,v1,v2,v3)
        if obj == None:
            self._createMemberObj(type,v1,v2,v3)
            obj = self._getMemberObj(type,v1,v2,v3)
        return obj

    def _getOrFailMemberObj(self,type,v1,v2=None,v3=None):
        obj = self._getMemberObj(type,v1,v2,v3)
        if obj == None:
            raise C2CException('Could not find mandatory "%s" object '\
                               'named "%s"' % (type,v1))
        return obj
        
    def isEqual(self, other):
        return self.__dict__ == other.__dict__
        
    def addMember(self, obj):
        if isarray(obj):
            for o in obj:
                self.members.append(o)
        else:
            self.members.append(obj)
        
class CiscoName(CiscoObject):
    """A cisco name"""
    ipAddr = None
    
    def __init__(self, c2c, parsedObj, name=None, ipAddr=None, desc=None, \
                 alreadyExist=False, color=None):
        if name != None:
            CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                                color)
            self.ipAddr = ipAddr
            self.alreadyExist = alreadyExist
        else:
            a = parsedObj.text.split(' ', 4)
            CiscoObject.__init__(self, c2c, parsedObj.text, a[2], desc, \
                                alreadyExist, color)
            self.ipAddr = a[1]
            if len(a) > 4:
                self.desc = a[4]
        self.dbClass = 'host_plain'
            
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,ipAddr=%s,desc=%s,alias=%s)\n" % (self.name,self.ipAddr,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '''# Creating new host: {0}
create host_plain {0}
modify network_objects {0} ipaddr {1}
modify network_objects {0} comments "{2}"
modify network_objects {0} color "{3}"
update network_objects {0}
'''.format(self.name, self.ipAddr, self.getDesc(), self.color)
 
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoHost(CiscoName):
    """A cisco host"""
    
    def __init__(self, c2c, parsedObj, name=None, ipAddr=None, desc=None, \
                 alreadyExist=False, color=None):
        if name != None:
            CiscoName.__init__(self, c2c, None, name, ipAddr, desc, \
                               alreadyExist, color)
        else:
            a = parsedObj.text.split(' ', 2)
            CiscoName.__init__(self, c2c, parsedObj, color=color)
            child = self._parseChildren(parsedObj)
            self.ipAddr = child['host'][0]
            if child.has_key('description'):
                self.desc = child['description'][0]
            self.alreadyExist = alreadyExist
                    
    def toString(self,indent='',verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,ipAddr=%s,desc=%s,alias=%s)\n" % (self.name,self.ipAddr,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret
        
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
        # TODO: Remove this old check
        if ipAddr != None and not isipaddress(ipAddr):
            print(parsedObj)
            print(name)
            print(mask)
            raise C2CException('error')

        if name != None:
            CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                                color)
            self.ipAddr = ipAddr
            self.mask = mask
        else:
            a = parsedObj.text.split(' ', 2)
            CiscoObject.__init__(self, c2c, parsedObj.text, a[2], '', \
                                 alreadyExist, color)
            child = self._parseChildren(parsedObj)
            self.ipAddr,self.mask = child['subnet'][0].split(' ',1)
            if child.has_key('description'):
                self.desc = child['description'][0]

        self.dbClass = 'network'
            
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,ipAddr=%s/%s,desc=%s,alias=%s)\n" % (self.name,self.ipAddr,self.mask,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '''# Creating new subnet: {0}
create network {0}
modify network_objects {0} ipaddr {1}
modify network_objects {0} netmask {2}
modify network_objects {0} comments "{3}"
modify network_objects {0} color "{4}"
update network_objects {0}
'''.format(self.name, self.ipAddr, self.mask, \
            self.getDesc(), self.color)
        
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoRange(CiscoObject):
    """A cisco range"""
    first = None
    last = None
    
    def __init__(self, c2c, parsedObj, name=None, ipAddrFirst=None, \
                 ipAddrLast=None, desc=None, alreadyExist=False, color=None):
        if name != None:
            CiscoObject.__init__(self, c2c, None, name, desc, alreadyExist, \
                                color)
            self.first = ipAddrFirst
            self.last = ipAddrLast
        else:
            a = parsedObj.text.split(' ', 2)
            CiscoObject.__init__(self, c2c, parsedObj.text, a[2], '', \
                                 alreadyExist, color)
            
            child = self._parseChildren(parsedObj)
            self.first,self.last = child['range'][0].split(' ',1)
            if child.has_key('description'):
                self.desc = child['description'][0]
                
        self.dbClass = 'address_range'
            
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,ipRange=%s/%s,desc=%s)\n" % (self.name,self.first,self.last,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '''# Creating new range: {0}
create address_range {0}
modify network_objects {0} ipaddr_first {1}
modify network_objects {0} ipaddr_last {2}
modify network_objects {0} comments "{3}"
modify network_objects {0} color "{4}"
update network_objects {0}
'''.format(self.name, self.first, self.last, \
            self.getDesc(), self.color)        
        
    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoSinglePort(CiscoPort):
    """A cisco name"""
    port = None
    sport = None # Source port. TODO: Not defined yet but would be useful. 
    
    def __init__(self, c2c, parsedObj, name=None, proto=None, port=None, desc=None, alreadyExist=False):
        if parsedObj != None:
            pass
        elif name != None:
            CiscoPort.__init__(self, c2c, name, alreadyExist)    
        else:
            if proto == 'tcp':
                CiscoPort.__init__(self, c2c, TCP_PREFIX+port, alreadyExist)
                self.dbClass = 'tcp_service'
            elif proto == 'udp':
                CiscoPort.__init__(self, c2c, UDP_PREFIX+port, alreadyExist)
                self.dbClass = 'udp_service'
            else:
                raise C2CException('Invalid Protocol: %s' % proto)
                
        if proto != None:
            self.proto = proto
            self.port = port
            self.desc = desc
        elif parsedObj != None:
            a = parsedObj.text.split(' ', 2)
            name = a[2]
            
            child = self._parseChildren(parsedObj)
            if child.has_key('service'):
                for portObj in child['service']:
                    # Possible values of service:
                    # service udp destination eq 123
                    # service udp destination eq whois
                    portObj = portObj.rstrip()
                    
                    self.proto,direction,portCmp,port = portObj.split(' ',3)
                    self.port = self._convertPort(port)
                    
                    # This is called late because proto must be defined first.
                    CiscoPort.__init__(self, c2c, name, alreadyExist)
                    
                    
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,port=%s,desc=%s,alias=%s)\n" % (self.name,self.port,self.getDesc(),';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        return '''# Creating new port: {1}
create {0} {1}
modify services {1} port {2}
modify services {1} comments "{3}"
update services {1}
'''.format(self._toDBEditType(), self.name, self.port, self.getDesc())
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoAnyPort(CiscoSinglePort):
    """A cisco port"""
    
    def __init__(self, c2c):
        CiscoSinglePort.__init__(self, c2c, None, 'any', None, 0, None, True)
        
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' globals:any\n".format(groupName)
        
class CiscoPortRange(CiscoPort):
    """A cisco name"""
    first = None
    last = None
    
    def __init__(self, c2c, parsedObj, name=None, proto=None, first=None, last=None, desc=None, alreadyExist=False):
        if parsedObj != None:
            pass
        elif name == None:
            if proto == 'tcp':
                CiscoPort.__init__(self, c2c, TCP_PREFIX+first+'-'+last, alreadyExist)
            elif proto == 'udp':
                CiscoPort.__init__(self, c2c, UDP_PREFIX+first+'-'+last, alreadyExist)        
            else:
                raise C2CException('Invalid Protocol')
        else:
            CiscoPort.__init__(self, c2c, name)
            
        if proto != None:
            self.proto = proto
            self.first = first
            self.last = last
            self.desc = desc
        else:
            a = parsedObj.text.split(' ', 2)
            name = a[2]
            
            child = self._parseChildren(parsedObj)
            if child.has_key('service'):
                for portObj in child['service']:
                    # Possible values of service:
                    # service udp destination range 123 456
                    portObj = portObj.rstrip()
                    self.proto,direction,portCmp,self.first,self.last = portObj.split(' ',4)
                    
                    # This is called late because proto must be defined first.
                    CiscoPort.__init__(self, c2c, name, alreadyExist)
        
    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,port=%s-%s,desc=%s)\n" % (self.name,self.first,self.last,self.getDesc())
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret
        
    def toDBEdit(self):
        return '''# Creating new port range: {1}
create {0} {1}
modify services {1} port {2}-{3}
modify services {1} comments "{4}"
update services {1}
'''.format(self._toDBEditType(), self.name, self.first, self.last, self.getDesc())
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoProto(CiscoPort):
    """A cisco icmp packet"""
    
    def __init__(self, c2c, name=None, desc=None, alreadyExist=False):
        CiscoPort.__init__(self, c2c, name, alreadyExist)
        self.desc = desc

    def toString(self, indent='', verify=False):
        ret = ''
        ret += indent+self.getClass()+"(name=%s,desc=%s,alias=%s)\n" % (self.name,self.getDesc(),';'.join(self.alias))
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
        if name != None:
            CiscoGroup.__init__(self, c2c, None, name, members, desc, \
                                alreadyExist, color)
        else:
            a = parsedObj.text.split(' ', 2)
            name = a[2]
            CiscoGroup.__init__(self, c2c, parsedObj.text, name, None, '', \
                                alreadyExist, color)
            self.dbClass = 'network_object_group'
            
            child = self._parseChildren(parsedObj)
            # For all network objects
            if child.has_key('network-object'):
                for network in child['network-object']:
                    # Possible values of network-object:
                    # network-object 206.156.53.0 255.255.255.0
                    # network-object object nG_IM2-NFA_10.253.252.145
                    # network-object host 10.253.216.74
                    v1,v2 = network.split(' ',1)
                    obj = self._getMemberObj(v1,v2)
                    if obj:
                        self.members.append(obj)
                    else:
                        self._createMemberObj(v1,v2)
                        
            # For all group objects
            if child.has_key('group-object'):
                for groupName in child['group-object']:
                    obj = self._getMemberObj('host-group',groupName)
                    if obj:
                        self.members.append(obj)
                    else:
                        self._createMemberObj('host-group',groupName)
                        
            if child.has_key('description'):
                self.desc = child['description'][0]
        
    def toString(self, indent='', verify=False):
        ret = indent+self.getClass()+"(name=%s,desc=%s,nbMembers=%i,alias=%s)\n" % (self.name,self.getDesc(),len(self.members),';'.join(self.alias))
        for member in self.members:
            ret += indent+member.toString(indent+' ')
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        ret = ''
        # Write header
        ret += '''# Creating new network group: {0}
create network_object_group {0}
modify network_objects {0} comments "{1}"
modify network_objects {0} color "{2}"
 '''.format(self.name, self.getDesc(), self.color)
        # Write all members
        for mem in self.members:
            ret += mem.toDBEditElement(self.name)
        # Write footer
        ret += '''update network_objects {0}
 '''.format(self.name)
        return ret

    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoPortGroup(CiscoGroup):
    """A cisco service"""
    
    def __init__(self, c2c, parsedObj):
        a = parsedObj.text.split(' ', 3)
        grpType = a[1]
        name = a[2]
        CiscoGroup.__init__(self, c2c, parsedObj.text, name)
        self.dbClass = 'service_group'
                
        if grpType == 'protocol':
            child = self._parseChildren(parsedObj)
            if child.has_key('protocol-object'):
                if ('tcp' in child['protocol-object'] and 'udp' in child['protocol-object']) \
                  or 'ip' in child['protocol-object']:
                    obj = self._getMemberObj('port','any')
                    if obj:
                        if isarray(obj):
                            for o in obj:
                                self.members.append(o)
                        else:
                            self.members.append(obj)
                    else:
                        self._createMemberObj('port','any')
                        obj = self._getMemberObj('port','any')
                    obj.addAlias(name)
        else:
            child = self._parseChildren(parsedObj)
            # For all portObj objects
            if child.has_key('port-object'):
                # if port-object, group object-group should contain a protocol
                proto = a[3]
                for portObj in child['port-object']:
                    # Possible values of port-object:
                    # port-object range 8194 8198
                    # port-object eq 4321
                    # port-object eq whois
                    portCmp,port = portObj.split(' ',1)
                    port = self._convertPort(port)
                    if ' ' in port:        # After conversion, the port could be a range (ex: sip)
                        portCmp = 'range'
                        
                    if portCmp == 'eq':
                        obj = self._getMemberObj(portCmp,proto,port)
                    elif portCmp == 'range':
                        first,last = port.split(' ',1)
                        obj = self._getMemberObj(portCmp,proto,first,last)
                    else:
                        raise C2CException('This identifier is not supported: %s' % portCmp)
                        
                    if obj:
                        self.addMember(obj)
                    else:
                        if portCmp == 'eq':
                            self._createMemberObj(portCmp,proto,port)
                        elif portCmp == 'range':
                            self._createMemberObj(portCmp,proto,first,last)
                        else:
                            raise C2CException('This identifier is not supported: %s' % portCmp)
                            
            if child.has_key('service-object'):
                for portObj in child['service-object']:
                    # Possible values of service-object:
                    # service-object tcp destination range 19305 19309 
                    # service-object udp destination eq 123
                    # service-object udp destination eq whois
                    # service-object icmp|ip|tcp|udp
                    # service-object object TCP_4443
                    portObj = portObj.rstrip()
                    if portObj == 'icmp':         # This means all icmp. 
                        portCmp = 'icmp'
                        obj = self._getMemberObj(portCmp,'any')
                    elif portObj == 'ip':
                        portCmp = 'ip'
                        obj = self._getMemberObj('port','any')
                    elif portObj == 'tcp':
                        portCmp = 'tcp'
                        obj = self._getMemberObj('port','any')
                    elif portObj == 'udp': 
                        portCmp = 'udp'
                        obj = self._getMemberObj('port','any')
                    elif portObj == 'esp':         # This means all esp (IPSec phase1). 
                        portCmp = 'esp'
                        obj = self._getMemberObj(portCmp,'any')
                    elif portObj == 'ah':         # This means all ah (IPSec phase2). 
                        portCmp = 'ah'
                        obj = self._getMemberObj(portCmp,'any')
                    elif portObj == 'object':         # This means a previously defined port (Range or Single)
                        portCmp = 'port-object'
                        obj = self._getMemberObj(portCmp,None)
                    else:
                        try:
                            proto,direction,portCmp,port = portObj.split(' ',3)
                            port = self._convertPort(port)
                            if ' ' in port and port[-1:] != ' ':        # After conversion, the port could be a range (ex: sip)
                                portCmp = 'range'
                        except ValueError:
                            object,name = portObj.split(' ',1)
                            portCmp = 'port-object'
                            
                        if portCmp == 'eq':
                            obj = self._getMemberObj(portCmp,proto,port)
                        elif portCmp == 'range':
                            first,last = port.split(' ',1)
                            obj = self._getMemberObj(portCmp,proto,first,last)
                        elif portCmp == 'port-object':
                            obj = self._getMemberObj(portCmp,name)
                        else:
                            raise C2CException('This identifier is not supported: %s' % portCmp)
                            
                    if obj:
                        self.addMember(obj)
                    else:
                        if portCmp == 'eq':
                            self._createMemberObj(portCmp,proto,port)
                        elif portCmp == 'range':
                            self._createMemberObj(portCmp,proto,first,last)
                        elif portCmp == 'icmp':
                            self._createMemberObj(portCmp,'any')
                        elif portCmp == 'ip':
                            self._createMemberObj('port','any')
                        elif portCmp == 'tcp':
                            self._createMemberObj('port','any')
                        elif portCmp == 'udp':
                            self._createMemberObj('port','any')                            
                        elif portCmp == 'esp':
                            self._createMemberObj(portCmp,'any')
                        elif portCmp == 'ah':
                            self._createMemberObj(portCmp,'any')
                        else:
                            raise C2CException('This identifier is not supported: %s' % portCmp)
                            
            if child.has_key('group-object'):
                for portObj in child['group-object']:
                    # Possible values of group-object:
                    # group-object RPC_High_ports_TCP
                    obj = self._getMemberObj('port-group',portObj)
                    if obj:
                        self.addMember(obj)
                    else:
                        self._createMemberObj('port-group',portObj)
            
            if child.has_key('icmp-object'):
                proto = 'icmp'
                for icmpObj in child['icmp-object']:
                    # icmp-object echo-reply
                    # icmp-object time-exceeded
                    # icmp-object unreachable
                    # icmp-object echo
                    obj = self._getMemberObj(proto,icmpObj)
                    if obj:
                        self.addMember(obj)
                    else:
                        self._createMemberObj(proto,icmpObj)                    
                    
        if child.has_key('description'):
            self.desc = child['description'][0]
        
    def toString(self, indent='', verify=False):
        ret = indent+self.getClass()+"(name=%s,desc=%s,nbMembers=%i)\n" % (self.name,self.getDesc(),len(self.members))
        for member in self.members:
            ret += indent+' '+member.toString(indent)
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        ret = ''
        # Write header
        ret += '''# Creating new port group: {0}
create service_group {0}
modify services {0} comments "{1}"
 '''.format(self.name, self.getDesc())
        # Write all members
        for mem in self.members:
            ret += mem.toDBEditElement(self.name)
        # Write footer
        ret += '''update services {0}
 '''.format(self.name)
        return ret
    
    def toDBEditElement(self, groupName):
        return "addelement services {0} '' services:{1}\n".format(groupName, self.name)

class CiscoNatRule(CiscoGroup):
 # Doc: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk39327
 #    => Notes about NAT on load sharing vs high availability
 #
 #modify network_objects host1 add_adtr_rule true
 #modify network_objects host1 NAT NAT
 #modify network_objects host1 NAT:valid_ipaddr 192.168.1.100
 #modify network_objects host1 NAT:netobj_adtr_method adtr_static|adtr_hide
 #modify network_objects host1 NAT:the_firewalling_obj network_objects:gateway1|globals:All
 #update network_objects host1

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
        
        obj = self._getMemberObj('object',nattedObjName)
        if obj:
            self.internalObj = obj
        else:
            raise C2CException('Cannot find nat internal object %s' % nattedObjName)
        
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
                    obj = self._getMemberObj(type,natIp)
                    if obj == None:
                        self._createMemberObj(type,natIp)
                        obj = self._getMemberObj(type,natIp)
                    self.externalObj = obj
                else:
                    raise C2CException('Unsupported NAT rule: %s' % network)
                    
                self.type = type
                
        if child.has_key('description'):
            self.desc = child['description'][0]
        
    def toString(self, indent='', verify=False):
        extName = ''
        if self.externalObj != None: extName = self.externalObj.name 
        ret = ''
        ret += indent+self.getClass()+"(Type=%s,InternalIP=%s,ExternalIP=%s,alias=%s)\n" % (self.type,self.internalObj.name,extName,';'.join(self.alias))
        if verify and self.getVerify():
            ret += indent+self.getVerify()
        return ret

    def toDBEdit(self):
        if self.type == 'hide':
            return '''# Creating new nat rule: {0}
modify network_objects {0} add_adtr_rule true
modify network_objects {0} NAT NAT
modify network_objects {0} NAT:valid_addr_name {0}
modify network_objects {0} NAT:valid_ipaddr 0.0.0.0
modify network_objects {0} NAT:valid_ipaddr6 ::
modify network_objects {0} NAT:netobj_adtr_method adtr_hide
modify network_objects {0} NAT:the_firewalling_obj network_objects:{1}
update network_objects {0}
'''.format(self.internalObj.name, self.installOn)
        else:
            return '''# Creating new nat rule: {0}
modify network_objects {0} add_adtr_rule true
modify network_objects {0} NAT NAT
modify network_objects {0} NAT:valid_ipaddr {1}
modify network_objects {0} NAT:netobj_adtr_method adtr_static
modify network_objects {0} NAT:the_firewalling_obj network_objects:{2}
update network_objects {0}
'''.format(self.internalObj.name, self.externalObj.ipAddr, self.installOn)

    def toDBEditElement(self, groupName):
        return "addelement network_objects {0} '' network_objects:{1}\n".format(groupName, self.name)

class CiscoACLRule(CiscoGroup):
 # Doc: https://sc1.checkpoint.com/documents/R77/CP_R77_CLI_ReferenceGuide_WebAdmin/105997.htm
 # Creating new rule: {0}
 # addelement fw_policies ##{1} rule security_rule
 # modify fw_policies ##{1} rule:0:comments "{2}"
 # modify fw_policies ##{1} rule:0:disabled false
 # rmbyindex fw_policies ##{1} rule:0:track 0
 # addelement fw_policies ##{1} rule:0:track tracks:None
 # addelement fw_policies ##{1} rule:0:time globals:Any
 # addelement fw_policies ##{1} rule:0:install:'' globals:Any
 # rmbyindex fw_policies ##{1} rule:0:action 0
 # addelement fw_policies ##{1} rule:0:action accept_action:accept
 # addelement fw_policies ##{1} rule:0:src:'' globals:Any
 # modify fw_policies ##{1} rule:0:src:op ''
 # addelement fw_policies ##{1} rule:0:dst:'' globals:Any
 # modify fw_policies ##{1} rule:0:dst:op ''
 # addelement fw_policies ##{1} rule:0:services:'' globals:Any
 # modify fw_policies ##{1} rule:0:services:op ''
 #
 # Working way to create new firewall rules
 # Note: after the first line, an item is appended so the number of rules must 
 # be known
 # addelement fw_policies ##Standard rule security_rule
 # modify fw_policies ##Standard rule:0:disabled false
 # modify fw_policies ##Standard rule:0:src rule_source
 # modify fw_policies ##Standard rule:0:dst rule_destination
 # modify fw_policies ##Standard rule:0:services rule_services
 # modify fw_policies ##Standard rule:0:install rule_install
 # addelement fw_policies ##Standard rule:0:src:'' network_objects:Net_192.168.3.0
 # addelement fw_policies ##Standard rule:0:dst:'' network_objects:Net_192.168.3.0
 # addelement fw_policies ##Standard rule:0:services:'' globals:Any
 # addelement fw_policies ##Standard rule:0:install:'' globals:Any
 # addelement fw_policies ##Standard rule:0:action drop_action:drop
 #
    src = None
    dst = None
    port = None
    action = None
    time = None
    tracks = None
    installOn = None
    policy = DEFAULT_POLICY
    disabled = False
    text = None
    
    def __init__(self, c2c, parsedObj, remark=None, policy=None,\
                 installOn=None, forceLog=None):
        # access-list perim extended permit tcp object-group In-Domain_Servers \
        # object-group DM_INLINE_NETWORK_2 object-group In-Domain-TCP 
        CiscoGroup.__init__(self, c2c, parsedObj.text, parsedObj.name)
        self.desc = remark
        self.policy = policy
        self.installOn = installOn
        self.src = []
        self.dst = []
        self.port = []
        self.text = parsedObj.text
        self._buildFromParsedObj(parsedObj)
        if forceLog:
            self.tracks = True
    
    #ip access-list extended ISO_NE_OUT_(GI0/0.817)
    # permit tcp any any established
    # permit icmp host 172.19.33.11 object-group ISO_NET
    # deny   ip any any log
    #ip access-list extended PRIO1
    # permit ospf any any
    #ip access-list extended PRIO2
    # permit ip host 10.112.191.191 host 10.112.143.242
    # permit udp 172.18.0.0 0.0.255.255 host 10.112.191.251 eq domain
    # permit udp 172.18.0.0 0.0.255.255 host 10.112.191.251 eq domain ntp netbios-ns
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
        proto = self._convertProto(parsedObj.proto)
        proto_m = parsedObj.proto_method
        port = parsedObj.dst_port
        port_m = parsedObj.dst_port_method
        #print("%s %s %s %s" % (proto,proto_m,port,port_m))
        if proto_m == 'proto':
            if port_m == 'eq':
                portList = port.split(' ')
                ret = []
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
                return [self._getOrCreateMemberObj('port-group',port)]
            elif port_m == None:        # this means any
                return [self._getAnyPort(proto)]
        elif proto_m == 'object-group':
            obj = self._getMemberObj('port-group',proto)
            if obj:
                return [obj]
            else:
                #raise C2CException('Proto method "%s" not implemented yet.' % \
                #                  proto_m)
                raise C2CException('Proto "%s" is not defined.' % \
                                  proto)
        elif parsedObj.parent.type == 'standard':   # standard = any
            return [self._getAnyPort('ip')]
        elif proto_m == 'remark':
            return None
        else:
            print("%s" % (parsedObj.text))
            print("%s %s %s %s" % (proto,proto_m,port,port_m))
            raise C2CException("Unrecognized proto/port")
        
    def _getAnyPort(self, proto):
        if proto in ['ip','tcp','udp']:
            type = 'port'
        elif proto in ['icmp','ospf','esp','ah','ahp','vrrp','skip','gre']:
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
        ret = ''
         #addelement fw_policies ##{1} rule security_rule
        ret += '''# Creating new rule: {0}
modify fw_policies ##{1} rule:{11}:name "{0}"
modify fw_policies ##{1} rule:{11}:comments "{2}"
modify fw_policies ##{1} rule:{11}:disabled {10}
rmbyindex fw_policies ##{1} rule:{11}:track 0
addelement fw_policies ##{1} rule:{11}:track {3}
addelement fw_policies ##{1} rule:{11}:time {4}
addelement fw_policies ##{1} rule:{11}:install:'' {5}
rmbyindex fw_policies ##{1} rule:{11}:action 0
addelement fw_policies ##{1} rule:{11}:action {6}
{7} modify fw_policies ##{1} rule:{11}:src:op ''
{8} modify fw_policies ##{1} rule:{11}:dst:op ''
{9} modify fw_policies ##{1} rule:{11}:services:op ''
'''.format(self.name, \
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
        ret = ''
        ret += '''# Creating new rule: {0}
addelement fw_policies ##{1} rule security_rule
modify fw_policies ##{1} rule:{11}:name "{0}"
modify fw_policies ##{1} rule:{11}:comments "{2}"
modify fw_policies ##{1} rule:{11}:disabled {10}
modify fw_policies ##{1} rule:{11}:src rule_source
modify fw_policies ##{1} rule:{11}:dst rule_destination
modify fw_policies ##{1} rule:{11}:services rule_services
modify fw_policies ##{1} rule:{11}:install rule_install
{7}modify fw_policies ##{1} rule:{11}:src:op ''
{8}modify fw_policies ##{1} rule:{11}:dst:op ''
{9}modify fw_policies ##{1} rule:{11}:services:op ''
addelement fw_policies ##{1} rule:{11}:action {6}
addelement fw_policies ##{1} rule:{11}:install:'' {5}
rmbyindex fw_policies ##{1} rule:{11}:track 0
addelement fw_policies ##{1} rule:{11}:track {3}
addelement fw_policies ##{1} rule:{11}:time {4}
'''.format(self.name, \
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
        return [obj for obj in self.parse.find_objects("^name")]
        
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
        return self.parse.find_objects(r"^access-list\s\w+\sextended")
    
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
#    cpPortsImCt = 0    # TODO: Delete
#    cpPortsCt = 0      # TODO: Delete
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
        print(MSG_PREFIX+'Importing all objects except groups.')
        self._importCheckpointNetworkObjects(xmlNetworkObjectsFile)
        self._importHosts(self.parser.getHostObjs())
        self._importNets(self.parser.getNetObjs())
        self._importRanges(self.parser.getRangeObjs())
        #self._importNames(self.parser.getNameObjs())        # Names are Legacy. Do not import as objects.
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
            self._importACLRules(self.parser.getACLRules())
            self._importIPACLRules(self.parser.getIPACLRules())
            self._fixACLRuleRedundancy()
            if self.disableRules:
                self._disableRules()
        
        self.netGrCt = len(self.findObjByType(['CiscoNetGroup']))    # Remove this 
        
        if self.flattenInlineNetGroups:
            self._flattenInlineNetGroups()

        if self.flattenInlineSvcGroups:
            self._flattenInlineSvcGroups()
            
    def _importNames(self, names):
        print(MSG_PREFIX+'Importing all names.')
        self.nameImCt = 0
        for n in names:
            self.addObj(CiscoName(self, n, color=self.color))
            self.nameImCt += 1
        
    def _importHosts(self, hosts):
        print(MSG_PREFIX+'Importing all hosts.')
        self.hostImCt = 0
        for h in hosts:
            self.addObj(CiscoHost(self, h, color=self.color))
            self.hostImCt += 1

    def _importNets(self, networks):
        print(MSG_PREFIX+'Importing all networks.')
        self.netImCt = 0
        for n in networks:
            self.addObj(CiscoNet(self, n, color=self.color))
            self.netImCt += 1

    def _importRanges(self, ranges):
        print(MSG_PREFIX+'Importing all ranges.')
        self.rangeImCt = 0
        for r in ranges:
            self.addObj(CiscoRange(self, r, color=self.color))
            self.rangeImCt += 1
            
    def _importSinglePorts(self, ports):
        print(MSG_PREFIX+'Importing all single ports objects.')
        self.singlePortImCt = 0
        for p in ports:                    
            self.addObj(CiscoSinglePort(self, p))    
            self.singlePortImCt += 1
            
    def _importPortRanges(self, ports):
        print(MSG_PREFIX+'Importing all port ranges objects.')
        self.portRangeImCt = 0
        for p in ports:                    
            self.addObj(CiscoPortRange(self, p))    
            self.portRangeImCt += 1
            
    def _importNetGroups(self, groups):
        print(MSG_PREFIX+'Importing all net/host/range groups.')
        self.netGrImCt = 0
        for newGrp in groups:                    
            self.addObj(CiscoNetGroup(self, newGrp, color=self.color))    
            self.netGrImCt += 1
            
    def _importPortGroups(self, groups):
        print(MSG_PREFIX+'Importing all port groups.')
        self.portGrCt = 0
        for newGrp in groups:        
            self.addObj(CiscoPortGroup(self, newGrp))        
            self.portGrCt += 1
            
    def _importProtoGroups(self, groups):
        print(MSG_PREFIX+'Importing all protocol groups.')
        for newGrp in groups:        
            obj = CiscoPortGroup(self, newGrp)
            if 'any' in [member.name for member in obj.members]:
                self.addObj(member)
                self.portGrCt += 1
            #else:
            #    print('WTF: '+obj.toString())
            #    self.addObj(obj)
            
    def _importNatRules(self, rules):
        print(MSG_PREFIX+'Importing all NAT rules.')
        self.natRuCt = 0
        for r in rules:        
            self.addObj(CiscoNatRule(self, r, self.natInstallOn))    
            self.natRuCt += 1
            
    def _importACLRules(self, rules):
        print(MSG_PREFIX+'Importing all firewall rules. (access-list)')
        aclNames = []
        self.aclRuImCt = 0
        rem = None
        for i in range(0,len(rules)-1):    
            cmd,aclName,type,rest = rules[i].text.split(' ', 3)
            if type == 'remark':
                rem = rest
            elif type == 'extended':
                self.addObj(CiscoACLRule(self, rules[i], rem, \
                                         self.policy, self.installOn, \
                                         forceLog = self.forceLog))
                self.aclRuImCt += 1
                rem = None
            else:
                raise C2CException('Invalid ACL type. It should be extended or remark only. Value was: "%s"' % type)
    
    def _importIPACLRules(self, rules):
        '''
        Conditions for not importing a rule:
            - Contain attribute "established"
            - Contain a source port
        '''
        print(MSG_PREFIX+'Importing all firewall rules. (ip access-list)')
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
                        self.aclRuEsCt += 1
                    elif child.src_port_method:
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
                if (obj.getClass() == 'CiscoACLRule')]:
            aclRule.disabled = True

    def _importCheckpointPorts(self, xmlPortsFile):
        print(MSG_PREFIX+'Importing Checkpoint ports objects')
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
                        self.addObj(CiscoPortRange(self, None, name, proto, first, '65535', comments, True))
                        self.portRangeCpCt += 1
                    elif port[0] == '<':
                        self.addObj(CiscoPortRange(self, None, name, proto, '0', port, comments, True))
                        self.portRangeCpCt += 1
                    elif '-' in port:
                        first,last = port.split('-',1)
                        self.addObj(CiscoPortRange(self, None, name, proto, first, last, comments, True))
                        self.portRangeCpCt += 1
                    else:
                        self.addObj(CiscoSinglePort(self, None, name, proto, port, comments, True))    
                        self.singlePortCpCt += 1
                elif port == '' and proto == 'icmp':
                    self.addObj(CiscoIcmp(self, name, comments, True))
                
        self._addIcmpAlias()
        
    def _importCheckpointNetworkObjects(self, xmlNetworkObjectsFile):
        print(MSG_PREFIX+'Importing Checkpoint network objects')
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
        print(MSG_PREFIX+'Adding ICMP Aliases')
        for icmpObj in [obj for obj in self.obj_list if obj.getClass() == 'CiscoIcmp']:
            for i, j in ICMP_DIC.iteritems():
                if icmpObj.name == j:
                    #if C2C_DEBUG: print(WARN_PREFIX+'Adding "%s" alias to "%s"' % (i,j))
                    icmpObj.addAlias(i)
        
    def _fixDuplicateNames(self):
        print(MSG_PREFIX+'Fixing duplicate names')
        for obj in self.obj_list:
            if obj.getClass() in NETOBJ_NAMED_CLASSES:
                foundList = self.findObjByName(obj.name)
                self._fixDuplicate(foundList, obj.name, obj.getClass())
        self.nameCt = len(self.findNewObjByType(['CiscoName']))
        self.hostCt = len(self.findNewObjByType(['CiscoHost']))

    def _fixDuplicateIp(self):
        print(MSG_PREFIX+'Fixing duplicate IP addresses')
        for obj in self.obj_list:
            if obj.getClass() in ['CiscoName','CiscoHost']:
                foundList = self.findHostByAddr(obj.ipAddr)
                self._fixDuplicate(foundList, obj.ipAddr, obj.getClass())
        self.nameCt = len(self.findNewObjByType(['CiscoName']))
        self.hostCt = len(self.findNewObjByType(['CiscoHost']))
                        
    def _fixDuplicateSubnet(self):
        print(MSG_PREFIX+'Fixing duplicate subnets')
        for obj in self.obj_list:
            if obj.getClass() in ['CiscoNet']:
                foundList = self.findNetByAddr(obj.ipAddr, obj.mask)
                self._fixDuplicate(foundList, obj.ipAddr+'/'+obj.mask, obj.getClass())
        self.netCt = len(self.findNewObjByType(['CiscoNet']))

    def _fixDuplicateRange(self):
        print(MSG_PREFIX+'Fixing duplicate ranges')
        for obj in self.obj_list:
            if obj.getClass() in ['CiscoRange']:
                foundList = self.findRangeByAddr(obj.first, obj.last)
                self._fixDuplicate(foundList, obj.first+'-'+obj.last, obj.getClass())
        self.rangeCt = len(self.findNewObjByType(['CiscoRange']))
        
    def _fixDuplicate(self, foundList, objName, objType):
        if len(foundList) == 1:
            pass
            #if C2C_DEBUG: print(MSG_PREFIX+'  %s: OK' % objName)
        else:
            if C2C_DEBUG: print(WARN_PREFIX+'  Object %s (%s) was found %i times. Deleting duplicates.' % (objName,objType,len(foundList)))
            if C2C_DEBUG: print(WARN_PREFIX+'    Keeping: %s (%s)' % (foundList[0].name,foundList[0].getClass()))
            for objToDel in foundList[1:]:
                self._cleanObj(foundList[0], objToDel)

    def _fixACLRuleRedundancy(self):
        print(MSG_PREFIX+'Merging redundant ACL rules')
        aclRules = [obj for obj in self.obj_list \
                     if obj.getClass() == 'CiscoACLRule']
        
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
        #print(WARN_PREFIX+'  The following objects will be merged.')
        if C2C_DEBUG: print(WARN_PREFIX+'Merging: %s' % obj1.toString('', False, False))
        if C2C_DEBUG: print(WARN_PREFIX+'With:    %s' % obj2.toString('', False, False))
        obj1.mergeWith(obj2)
        if C2C_DEBUG: print(WARN_PREFIX+'Result:  %s' % obj1.toString('', False, False))
    
    def _cleanObj(self, objToKeep, objToDel):
        objToKeep.addAlias(objToDel.name, '    ')
        for alias in objToDel.alias:
            objToKeep.addAlias(alias, '    ')
        for ciscoLine in objToDel.ciscoLines:
            objToKeep.addCiscoLine(ciscoLine, '    ')            
        if C2C_DEBUG: print(WARN_PREFIX+'    Deleting object: %s (%s)' % (objToDel.name, objToDel.getClass()))
        self.removeObj(objToDel)
        
    def _flattenInlineNetGroups(self):
        print(MSG_PREFIX+'Flattening DM_INLINE_NETWORK groups')
        aclRules = [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoACLRule')]        
        for fwr in aclRules:    # For each firewall rules
            for obj in fwr.src:    # For each source objects of the firewall rule.
                if (obj.getClass() == 'CiscoNetGroup' \
                    and obj.name.startswith(DM_INLINE_NET_PREFIX)):
                    self._flattenACLRuleAttribute(fwr, fwr.src, obj)
                    
            for obj in fwr.dst:    # For each source objects of the firewall rule.
                if (obj.getClass() == 'CiscoNetGroup' \
                    and obj.name.startswith(DM_INLINE_NET_PREFIX)):
                    self._flattenACLRuleAttribute(fwr, fwr.dst, obj)
        
    def _flattenInlineSvcGroups(self):
        print(MSG_PREFIX+'Flattening DM_INLINE_SERVICE groups')
        aclRules = [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoACLRule')]        
        for fwr in aclRules:    # For each firewall rules
            for obj in fwr.port:    # For each source objects of the firewall rule.
                if (obj.getClass() == 'CiscoPortGroup' \
                    and (obj.name.startswith(DM_INLINE_SVC_PREFIX) or \
                        obj.name.startswith(DM_INLINE_TCP_PREFIX) or \
                        obj.name.startswith(DM_INLINE_UDP_PREFIX))):
                    self._flattenACLRuleAttribute(fwr, fwr.port, obj)
        
    def _flattenACLRuleAttribute(self,fwr,fwrattr,group):
        if C2C_DEBUG: print(WARN_PREFIX+'    Flattening object %s on rule %s' % (group.name,fwr.name))
        # Add group's member to firewall attribute
        for m in group.members:
            fwrattr.append(m)
        # Remove group from firewall attribute
        fwrattr.remove(group)
        group.alreadyExist = True

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
    
    def findHostByAddr(self,ipAddr):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in HOST_CLASSES \
                        and obj.ipAddr == ipAddr)]
                        
    def findNetByAddr(self,ipAddr,mask):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoNet') \
                        and obj.ipAddr == ipAddr and obj.mask == mask]
                        
    def findRangeByAddr(self,first,last):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoRange') \
                        and obj.first == first and obj.last == last]
                        
    def findServiceByNum(self,proto,port):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoSinglePort') \
                        and obj.proto == proto and obj.port == port]
    
    def findServiceByRange(self,proto,first,last):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoPortRange') \
                        and obj.proto == proto and obj.first == first and obj.last == last]
    
    def findServiceByName(self, name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in SVCOBJ_NAMED_CLASSES \
                        and obj.name.lower() == name.lower() or name in obj.alias)]
    
    def findIPServiceByName(self, name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() in ['CiscoSinglePort','CiscoPortRange','CiscoPortGroup','CiscoAnyPort','CiscoIcmp','CiscoAnyIcmp'] \
                        and obj.name.lower() == name.lower() or name in obj.alias)]
                        
    def findServiceGroupByName(self,name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoPortGroup') \
                        and (obj.name.lower() == name.lower() or name in obj.alias)]
                
    def findIcmpByName(self, name):
        return [obj for obj in self.obj_list \
                    if (obj.getClass() == 'CiscoIcmp' or obj.getClass() == 'CiscoAnyIcmp') \
                        and (obj.name.lower() == name.lower() or name in obj.alias)]
                        
    def findRuleByDesc(self, desc):
        return [obj for obj in self.obj_list \
                if (obj.getClass() == 'CiscoACLRule' and obj.desc == desc)]
                
    def findDuplicateNetGroup(self, obj2):
        return [obj1 for obj1 in self.obj_list if (obj1.getClass() == 'CiscoNetGroup' and obj1.isEqual(obj2))]
                
    def addObj(self,obj):
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
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoHost' or obj.getClass() == 'CiscoName')])
            
    def getAllPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() in ['CiscoSinglePort', 'CiscoPortRange'])])

    def getAllNonNumPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if ((obj.getClass() == 'CiscoSinglePort') and (not obj.port.isdigit()))])
        
    def getAllPortGroups(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoPortGroup')])

    def getAlreadyExistPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoSinglePort' and obj.alreadyExist == True)] + \
                    [obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoPortRange' and obj.alreadyExist == True )])

    def getNewPorts(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoSinglePort' and obj.alreadyExist == False)] + \
                    [obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoPortRange' and obj.alreadyExist == False )])
                    
    def getAllIcmp(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoIcmp')])

    def getNatRules(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoNatRule')])    
        
    def getACLRules(self):
        return ''.join([obj.toString() for obj in self.obj_list if (obj.getClass() == 'CiscoACLRule')])                        
                        
    def getSummary(self):
        # Print summary what was parsed.
        return """#
# Summary of the findings in "{0}"
#
# Number of names (before merge/cleanup): {1}
# Number of names (after merge/cleanup): {2}
# Number of hosts (imported from cisco file): {3}
# Number of hosts (imported from checkpoint xml): {4}
# Number of hosts (dynamically created): {5}
# Number of hosts (after merge/cleanup): {6}
# Number of subnet (imported from cisco file): {7}
# Number of subnet (imported from checkpoint xml): {8}
# Number of subnet (dynamically created): {9}
# Number of subnet (after merge/cleanup): {10}
# Number of range (imported from cisco file): {11}
# Number of range (imported from checkpoint xml): {12}
# Number of range (dynamically created): {13}
# Number of range (after merge/cleanup): {14}
# Number of subnet groups: {15}
# Number of service groups: {16}
# Number of nat rules: {17}
# Number of acl rules (not imported: established): {18}
# Number of acl rules (not imported: source port): {19}
# Number of acl rules (before merge/cleanup): {20}
# Number of acl rules (after merge/cleanup): {21}
# Number of single ports (imported from cisco file): {22}
# Number of single ports (imported from checkpoint xml): {23}
# Number of single ports (dynamically created): {24}
# Number of port range (imported from cisco file): {25}
# Number of port range (imported from checkpoint xml): {26}
# Number of port range (dynamically created): {27}
#""".format(self.importSrc, \
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
            self.portRangeCrCt \
    )
    
    def toDBEdit(self):
        return ''.join([obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoName')] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoHost' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoNet' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoRange' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoNetGroup' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoSinglePort' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoPortRange' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoPortGroup' and obj.alreadyExist == False)] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoNatRule') and obj.type in ['static','hide']] + \
                [obj.toDBEdit() for obj in self.obj_list if (obj.getClass() == 'CiscoACLRule')]) + \
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
                print(MSG_PREFIX+'Opening "%s"' % filePath)
                newC2c = Cisco2Checkpoint()
                newC2c.setDebug(self.debug)
                newC2c.setPolicy(self.policy)
                newC2c.setInstallOn(self.installOn)
                newC2c.setNatInstallOn(self.natInstallOn)
                newC2c.importConfig(cpPortsFile,cpNetObjFile,filePath,False)
                self.c2c_list.append(newC2c)
            else:
                #print(WARN_PREFIX+'Invalid file: %s' % filePath)
                pass
            
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
        print(MSG_PREFIX+'['+self.getClass()+'] Renaming duplicate network groups')
        for c2c in self.c2c_list:
            for grpObj in [obj for obj in c2c.obj_list if obj.getClass() in GROUP_CLASSES]:
                # if group is in other c2c instances
                dupGrpList = [obj for obj in make_flat([tmpc2c.obj_list for tmpc2c in self.c2c_list]) if obj.getClass() in GROUP_CLASSES and (grpObj.name == obj.name or grpObj.name in obj.alias)]
                if len(dupGrpList) > 0:
                    self._renameObjects(dupGrpList, grpObj.name)
        
    def _renameObjects(self, foundList, grpName):
        if len(foundList) == 1:
            pass
            #if C2C_DEBUG: print(MSG_PREFIX+'  %s: OK' % objName)
        else:
            if C2C_DEBUG: print(WARN_PREFIX+'  Object %s (%s) was found %i times in different config files. Renaming duplicates.' % (foundList[0].name,foundList[0].getClass(),len(foundList)))
            if C2C_DEBUG: print(WARN_PREFIX+'    Keeping: %s (%s)' % (foundList[0].name,foundList[0].c2c.configFile))
            num = 1
            for objToRename in foundList[1:]:
                #if grpName == objToRename.name:
                oldName = objToRename.name
                objToRename.name = objToRename.name+('-%02d' % num)
                if C2C_DEBUG: print(WARN_PREFIX+'    Renaming %s (%s) to %s' % (oldName,objToRename.c2c.configFile,objToRename.name))
                #elif grpName in objToRename.alias:
                #    oldName = objToRename.alias[pos]
                #    pos = objToRename.alias.index(grpName)
                #    objToRename.alias[pos] = objToRename.alias[pos]+('-%02d' % num)
                #    if C2C_DEBUG: print(WARN_PREFIX+'    Renaming alias %s (%s) to %s' % (oldName,objToRename.c2c.configFile,objToRename.alias[pos]))
                num += 1
                
    def _importAllSimpleObjects(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Importing objects except net groups and ACL rules')
        for c2c in self.c2c_list:
            self.obj_list += [obj for obj in c2c.obj_list if (obj.getClass() != 'CiscoACLRule' and obj.getClass() != 'CiscoNetGroup' and obj.getClass() != 'CiscoNatRule')]
            
    def _importAllNetGroups(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Importing groups')
        for c2c in self.c2c_list:
            self._importNetGroups(c2c.parser.getNetGroups())
            
    def _importAllNatRules(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Importing NAT rules')
        for c2c in self.c2c_list:
            self._importNatRules(c2c.parser.getNatRules())
            
    def _importAllACLRules(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Importing ACL rules')
        for c2c in self.c2c_list:
            self._importACLRules(c2c.parser.getACLRules())

    def _updateReferer(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Updating referer variable "c2c"')
        for obj in self.obj_list:
            obj.c2c = self
            
    def _fixDuplicateAny(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Fixing duplicate any objects')
        for obj in self.obj_list:
            if obj.getClass() in ANY_CLASSES:
                foundList = self.findObjByType(obj.getClass())
                self._fixDuplicate(foundList, obj.name, obj.getClass())
            
    def _fixDuplicatePorts(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Fixing duplicate ports')
        for obj in self.obj_list:
            if obj.getClass() in ['CiscoSinglePort']:
                foundList = self.findServiceByNum(obj.proto, obj.port)
                self._fixDuplicate(foundList, obj.name, obj.getClass())
                
    # TODO: Should check obj_list instead of c2c_list
    def _updateCounters(self):
        print(MSG_PREFIX+'['+self.getClass()+'] Updating counters')
        self.nameImCt = sum([obj.nameImCt for obj in self.c2c_list])
        self.nameCt = sum([obj.nameCt for obj in self.c2c_list])
        self.hostImCt = sum([obj.hostImCt for obj in self.c2c_list])
        self.hostCt = sum([obj.hostCt for obj in self.c2c_list])
        self.netImCt = sum([obj.netImCt for obj in self.c2c_list])
        self.netCt = sum([obj.netCt for obj in self.c2c_list])
        self.rangeImCt = sum([obj.rangeImCt for obj in self.c2c_list])
        self.rangeCt = sum([obj.rangeCt for obj in self.c2c_list])
        self.cpPortsImCt = sum([obj.cpPortsImCt for obj in self.c2c_list])
        self.cpPortsCt = sum([obj.cpPortsCt for obj in self.c2c_list])
        self.netGrImCt = sum([obj.netGrImCt for obj in self.c2c_list])
        self.netGrCt = sum([obj.netGrCt for obj in self.c2c_list])
        self.portGrCt = sum([obj.portGrCt for obj in self.c2c_list])
        self.natRuCt = sum([obj.natRuCt for obj in self.c2c_list])
        #self.aclRuImCt = sum([obj.aclRuImCt for obj in self.c2c_list])
        self.aclRuCt = len(self.findObjByType(['CiscoACLRule']))


