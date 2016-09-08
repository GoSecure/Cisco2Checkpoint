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

import re
from collections import Iterator

from ciscoconfparse import models_cisco
from ciscoconfparse import models_asa

import ciscoconfparse.ciscoconfparse as ccp

##
##-------------  ASA and IOS supported protocols, operators and port names
##
_PORT_SIMPLE_OP = 'eq|neq|lt|gt'
_PORT_NAMES = r'aol|bgp|chargen|cifs|citrix-ica|cmd|ctiqbe|daytime'\
                '|discard|domain|echo|exec|finger|tftp|ftp|ftp-data|gopher'\
                '|h323|hostname|http|https|ident|imap4|irc|kerberos|klogin'\
                '|kshell|ldap|ldaps|login|lotusnotes|lpd|netbios-ssn|nfs'\
                '|nntp|ntp|pcanywhere-data|pim-auto-rp|pop2|pop3|pptp|rsh'\
                '|rtsp|sip|smtp|sqlnet|ssh|sunrpc|tacacs|talk|telnet|uucp'\
                '|whois|www|netbios-ns|netbios-dgm|netbios-ss|snmptrap|snmp'\
                '|syslog|isakmp|bootps|bootpc|radius|\d+'
_ACL_PROTOCOLS = 'ip|tcp|udp|icmp|ahp|ah|eigrp|esp|gre|igmp|igrp|ipinip|ipsec'\
                '|ospf|pcp|pim|pptp|snp|\d+'
_ACL_ICMP_PROTOCOLS = 'alternate-address|conversion-error|echo-reply|echo'\
                '|information-reply|information-request|mask-reply'\
                '|mask-request|mobile-redirect|parameter-problem|redirect'\
                '|router-advertisement|router-solicitation|source-quench'\
                '|time-exceeded|timestamp-reply|timestamp-request|traceroute'\
                '|unreachable'
_ACL_LOGLEVELS = r'alerts|critical|debugging|emergencies|errors'\
                '|informational|notifications|warnings|[0-7]'
_IP_PROTO = 'tcp|udp|tcp-udp'

##
##-------------  Extension of an ASA object network 
##
_RE_ASA_NETOBJ_CHILD_STR = r"""(?:
(^\s+description(?P<description0>.+)$)
|(^\s+host\s+(?P<host1>\S+)$)
|(^\s+subnet\s+(?P<subnet2>\d+\.\d+\.\d+\.\d+)\s+(?P<mask2>\d+\.\d+\.\d+\.\d+)$)
|(^\s+range\s+(?P<range_low3>\d+\.\d+\.\d+\.\d+)\s+(?P<range_high3>\d+\.\d+\.\d+\.\d+)$)
)
"""
_RE_ASA_NETOBJ_CHILD = re.compile(_RE_ASA_NETOBJ_CHILD_STR, re.VERBOSE)
class ASAObjNetwork(models_asa.ASAObjNetwork):

    @property
    def name(self):
        retval = self.re_match_typed(r'^\s*object\snetwork\s+(\S.+)$',
            result_type=str, default='')
        return retval

    @property
    def description(self):
        regex = r"(^\s+description(?P<description0>.+)$)"
        retval = self.re_match_iter_typed(regex,
            result_type=str, default='')
        return retval

    @property
    def result_dict(self):
        retval = dict()

        for obj in self.children:
            ## Parse out 'service' and 'description' lines
            mm = _RE_ASA_NETOBJ_CHILD.search(obj.text)
            if not (mm is None):
                mm_r = mm.groupdict()
            else:
                mm_r = dict()
            
            # host...
            if mm_r.get('host1',None):
                retval['net_method'] = 'host'
                retval['ipaddr'] = mm_r['host1']
                retval['mask'] = '255.255.255.255'
            elif mm_r.get('subnet2',None):
                retval['net_method'] = 'subnet'
                retval['ipaddr'] = mm_r['subnet2']
                retval['mask'] = mm_r['mask2']
            elif mm_r.get('range_low3',None):
                retval['net_method'] = 'range'
                retval['ipaddr_low'] = mm_r['range_low3']
                retval['ipaddr_high'] = mm_r['range_high3']
            # description
            elif mm_r.get('description0',None):
                retval['description'] =  mm_r['description0']
            else:
                raise NotImplementedError("Cannot parse '{0}'".format(obj.text))
        return retval

##
##-------------  Extension of an ASA object service
##
_RE_ASA_SVCOBJ_CHILD_STR = r"""(?: # Non-capturing parentesis
# example:
# service tcp source range 1 65535 destination range 49152 65535
# service tcp source eq bgp destination eq 53
(^\s+description(?P<description0>.+))
|(^\s+service
  \s+(?P<protocol1>{0})
  (?:\s+source
    (?:                         # source port
      (?:\s+
        (?P<src_port_op1>{1})
        \s+(?P<src_port1>(?:(?:{2})\s?)+)
      )
      |(?:\s+range\s+(?P<src_port_low1>\d+)\s+(?P<src_port_high1>\d+))
      |(?:\s+object-group\s+(?P<src_service_group1>\S+))
    )
  )?
  (?:\s+destination
    (?:                         # destination port
      (?:\s+
        (?P<dst_port_op1>{1})
        \s+(?P<dst_port1>(?:(?:{2})\s?)+)
      )
      |(?:\s+range\s+(?P<dst_port_low1>\d+)\s+(?P<dst_port_high1>\d+))
      |(?:\s+object-group\s+(?P<dst_service_group1>\S+))
    )
  )
 )
)                               # Close non-capture parentesis
""".format(_IP_PROTO,_PORT_SIMPLE_OP,_PORT_NAMES)
_RE_ASA_SVCOBJ_CHILD = re.compile(_RE_ASA_SVCOBJ_CHILD_STR, re.VERBOSE)
class ASAObjService(models_asa.ASAObjService):

# TODO: Parent's class is defined differently. Determine why.
#
#   @classmethod
#    def is_object_for(cls, line="", re=re):
#        if 'object service ' in line[0:15].lower():
#            return True
#        return False
    @classmethod
    def is_object_for(cls, line="", re=re):
        if re.search(r'^(object\sservice)', line):
            return True
        return False

    @property
    def name(self):
        retval = self.re_match_typed(r'^\s*object\sservice\s+(\S.+)$',
            result_type=str, default='')
        return retval

    @property
    def description(self):
        regex = r"(^\s+description(?P<description0>.+)$)"
        retval = self.re_match_iter_typed(regex, result_type=str, default='')
        return retval

    def m_src_port(self,mm_r):
        if mm_r['src_port_low1']:
            return mm_r['src_port_low1'] + ' ' + mm_r['src_port_high1']
        return mm_r['src_port1'] or mm_r['src_service_group1'] \

    def m_src_port_method(self,mm_r):
        if mm_r['src_port_op1']:
            return mm_r['src_port_op1']
        elif mm_r['src_port_low1'] and mm_r['src_port_high1']:
            return 'range'
        elif mm_r['src_service_group1']:
            return 'object-group'

    def m_dst_port(self,mm_r):
        if mm_r['dst_port_low1']:
            return mm_r['dst_port_low1'] + ' ' + mm_r['dst_port_high1']
        return mm_r['dst_port1'] or mm_r['dst_service_group1'] \

    def m_dst_port_method(self,mm_r):
        if mm_r['dst_port_op1']:
            return mm_r['dst_port_op1']
        elif mm_r['dst_port_low1'] and mm_r['dst_port_high1']:
            return 'range'
        elif mm_r['dst_service_group1']:
            return 'object-group'

    @property
    def result_dict(self):
        """Return a list of strings which represent the source and destination 
        ports."""
        retval = dict()

        for obj in self.children:
            ## Parse out 'service' and 'description' lines
            mm = _RE_ASA_SVCOBJ_CHILD.search(obj.text)
            if not (mm is None):
                mm_r = mm.groupdict()
            else:
                mm_r = dict()
            
            # service ...
            if mm_r.get('protocol1',None):
                retval['proto'] = mm_r['protocol1']
                retval['proto_method'] = 'proto'
                retval['src_port'] = self.m_src_port(mm_r)
                retval['src_port_method'] =  self.m_src_port_method(mm_r)
                retval['src_port_op'] = mm_r['src_port_op1']
                retval['src_port_low'] = mm_r['src_port_low1']
                retval['src_port_high'] = mm_r['src_port_high1']
                retval['dst_port'] = self.m_dst_port(mm_r)
                retval['dst_port_method'] = self.m_dst_port_method(mm_r)
                retval['dst_port_op'] = mm_r['dst_port_op1']
                retval['dst_port_low'] = mm_r['dst_port_low1']
                retval['dst_port_high'] = mm_r['dst_port_high1']
            # description
            elif mm_r.get('description0',None):
                retval['description'] =  mm_r['description0']
            else:
                raise NotImplementedError("Cannot parse '{0}'".format(obj.text))
        return retval

##
##-------------  ASA object group protocol
##
_RE_ASA_PROTO_GROUP_CHILD_STR = r"""(?:
(^\s+description(?P<description0>.+)$)
|(^\s+protocol-object\s+(?P<protocol1>\S+)$)
)
"""
_RE_ASA_PROTO_GROUP_CHILD = re.compile(_RE_ASA_PROTO_GROUP_CHILD_STR, re.VERBOSE)
class ASAObjGroupProtocol(models_asa.BaseCfgLine):
    def __init__(self, *args, **kwargs):
        """Provide attributes on Cisco ASA Service groups"""
        super(ASAObjGroupProtocol, self).__init__(*args, **kwargs)
    
    def __repr__(self):
        return "<%s # %s '%s'>" % (self.classname, self.linenum, self.name)

    @classmethod
    def is_object_for(cls, line="", re=re):
        if re.search(r'^(object-group\sprotocol)', line):
            return True
        return False

    @property
    def name(self):
        retval = self.re_match_typed(r'^\s*object-group\sprotocol\s+(\S.+)$',
            result_type=str, default='')
        return retval

    @property
    def description(self):
        regex = r"(^\s+description(?P<description0>.+)$)"
        retval = self.re_match_iter_typed(regex,
            result_type=str, default='')
        return retval

    @property
    def result_dict(self):
        """Return a list of strings which represent the source and destination 
        ports."""
        retval = list()

        for obj in self.children:
            ## Parse out 'service' and 'description' lines
            mm = _RE_ASA_PROTO_GROUP_CHILD.search(obj.text)
            if not (mm is None):
                mm_r = mm.groupdict()
            else:
                mm_r = dict()
            
            # description
            if mm_r.get('description0',None):
                pass
            # protocol...
            elif mm_r.get('protocol1',None):
                retval.append(mm_r['protocol1'])
            else:
                raise NotImplementedError("Cannot parse '{0}'".format(obj.text))
        return retval

##
##-------------  ASA object-group service
##
## This class already exist in ciscoconfparse but I have rewrite it for 
## convenience and delivery delay.
## TODO: Extend the class instead of rewriting it.
##
# Difference between service-object and port-object
#
# object-group service WEB-PORTS tcp        <- proto is here
#   port-object eq www
#   port-object eq https
#
#  object-group service WEB-PORTS
#    service-object tcp eq 80               <- proto is here
#    service-object tcp eq 443              <- proto is here
#
_RE_ASA_SVCGROUP_CHILD_STR = r"""(?:                    # Non-capturing parentesis
# TODO: Add support for source ports in this regex
# Examples                                  group_suffix
#   service-object icmp|ip|tcp|udp|..       1
#   service-object udp destination eq dns   2
#   service-object tcp eq 80                2
#   service-object tcp range 5000 5005      3
#   service-object object TCP_4443          4
#   port-object eq https                    5
#   port-object range 1 1024                6
#   group-object RPC_High_ports_TCP         7
#   icmp-object echo-reply|time-exceeded|.. 8
#
(^\s+description\s+(?P<description0>.*)$)
|(^\s+service-object\s+(?P<protocol1>{3})$)
|(^\s+service-object\s+(?P<protocol2>{0})(?:\s+destination)?
    \s+(?P<dst_port_op2>{1})\s+(?P<dst_port2>{2}))
|(^\s+service-object\s+(?P<protocol3>{0})(?:\s+destination)?
    \s+(?P<dst_port_op3>range)\s+(?P<dst_port_low3>\d+)\s+(?P<dst_port_high3>\d+))
|(^\s+service-object\sobject\s+(?P<dst_object4>\S+))
|(^\s+port-object\s+(?P<dst_port_op5>{1})\s+(?P<dst_port5>{2}))
|(^\s+port-object\s+(?P<dst_port_op6>range)
    \s+(?P<dst_port_low6>\d+)\s+(?P<dst_port_high6>\d+))
|(^\s+group-object\s+(?P<dst_group7>\S+))
|(^\s+icmp-object\s+(?P<dst_icmp_msg8>\S+))
)                                                   # Close non-capture parens
""".format(_IP_PROTO,_PORT_SIMPLE_OP,_PORT_NAMES,_ACL_PROTOCOLS)
_RE_ASA_SVCGROUP_CHILD = re.compile(_RE_ASA_SVCGROUP_CHILD_STR, re.VERBOSE)
class ASAObjGroupService(models_asa.ASAObjGroupService):
    def __init__(self, *args, **kwargs):
        """Provide attributes on Cisco ASA Service groups"""
        super(ASAObjGroupService, self).__init__(*args, **kwargs)

        # Update to catch specific cases
        self.name = self.re_match_typed(r'object-group\s+service\s+(\S+)\s*.*$',
            result_type=str, default='')
    
    def __repr__(self):
        return "<%s # %s '%s'>" % (self.classname, self.linenum, self.name)

    @classmethod
    def is_object_for(cls, line="", re=re):
        if re.search(r'^(?:object-group\sservice)', line):
            return True
        return False

    @property
    def description(self):
        retval = self.re_match_iter_typed(r'\s+description\s+(\S+)$',
            result_type=str, default='')
        return retval

    @property
    def proto(self):
        retval = self.re_match(r'object-group\s+service\s+(?:\S+)\s+(\S+)?$',
            group=1, default=None)
        return retval

    def m_proto(self,mm_r):
        return mm_r['protocol1'] or mm_r['protocol2'] or mm_r['protocol3'] \
            or self.proto

    def m_proto_method(self,mm_r):
        if mm_r['protocol1']:
            return 'protocol'
        elif mm_r['protocol2'] or mm_r['protocol3']:
            return 'service-object'
        elif mm_r['dst_group7']:
            return 'group'
        elif mm_r['dst_object4']:
            return 'object'
        elif mm_r['dst_icmp_msg8']:
            return 'icmp'
        elif self.proto:
            return 'port-object'

    def m_dst_port(self,mm_r):
        if mm_r['dst_port_op3']:
            return mm_r['dst_port_low3'] + ' ' + mm_r['dst_port_high3']
        elif mm_r['dst_port_op6']:
            return mm_r['dst_port_low6'] + ' ' + mm_r['dst_port_high6']
        return mm_r['dst_port2'] or mm_r['dst_port5'] \
            or mm_r['dst_object4'] or mm_r['dst_group7'] or mm_r['dst_icmp_msg8']

    def m_dst_port_method(self,mm_r):
        if mm_r['dst_port_op2']:
            return mm_r['dst_port_op2']
        elif mm_r['dst_port_op5']:
            return mm_r['dst_port_op5']
        elif (mm_r['dst_port_low3'] and mm_r['dst_port_high3'])\
                or (mm_r['dst_port_low6'] and mm_r['dst_port_high6']):
            return 'range'
        elif mm_r['dst_object4']:
            return 'object'
        elif mm_r['dst_group7']:
            return 'group'
        elif mm_r['dst_icmp_msg8']:
            return 'icmp'

    def m_dst_port_op(self,mm_r):
        return mm_r['dst_port_op2'] or mm_r['dst_port_op3'] \
                or mm_r['dst_port_op5'] or mm_r['dst_port_op6']

    def m_service_name_exist(self,name):
        group_ports = self.confobj.object_group_service.get(name, None) \
                or self.confobj.object_service.get(name, None)
                
        if name==self.name:
            ## Throw an error when importing self
            raise ValueError("FATAL: Cannot recurse through group-object {0} in object-group service {1}".format(name, self.name))
        if (group_ports is None):
            return False
        return True

    @property
    def result_dict(self):
        """
        Return a list of objects which represent the protocol and ports 
        allowed by this object-group
        """
        retval = list()
        for obj in self.children:
            mm = _RE_ASA_SVCGROUP_CHILD.search(obj.text)
            if not (mm is None):
                mm_r = mm.groupdict()
            else:
                raise ValueError("[FATAL] models_asa cannot parse '{0}'"\
                                 .format(obj.text))
            
            if mm_r.get('description0',None):
                pass
            else:
                svc = dict()
                svc['proto'] = self.m_proto(mm_r)
                svc['proto_method'] = self.m_proto_method(mm_r)
                svc['dst_port'] = self.m_dst_port(mm_r)
                svc['dst_port_method'] = self.m_dst_port_method(mm_r)
                svc['dst_port_op'] = self.m_dst_port_op(mm_r)
                svc['dst_port_low'] = mm_r['dst_port_low3'] or mm_r['dst_port_low6']
                svc['dst_port_high'] = mm_r['dst_port_high3'] or mm_r['dst_port_low6']
        
                # Make sure the service group was defined before
                if self.m_dst_port_method(mm_r) in ['object','group']:
                    name = self.m_dst_port(mm_r)
                    if not self.m_service_name_exist(name):
                        raise ValueError("FATAL: Cannot find service object named {0}"\
                                         .format(name))

                retval.append(svc)

        return retval

##
##-------------  ASA object-group network
##
_RE_ASA_NETOBJECT_STR = r"""(?:                         # Non-capturing parenthesis
(^\s+description(?P<description0>.+)$)
|(^\s+network-object\s+host\s+(?P<host>\S+))
|(^\s+network-object
    (?:\s+network)?
    \s+(?P<network>\d+\.\d+\.\d+\.\d+)
    \s+(?P<netmask>\d+\.\d+\.\d+\.\d+))
|(^\s+network-object\s+object\s+(?P<object>\S+))
|(^\s+group-object\s+(?P<groupobject>\S+))
)                                                   # Close non-capture parens
"""
_RE_ASA_NETOBJECT = re.compile(_RE_ASA_NETOBJECT_STR, re.VERBOSE)
class ASAObjGroupNetwork(models_asa.ASAObjGroupNetwork):

    def __init__(self, *args, **kwargs):
        """Accept an ASA line number and initialize family relationship
        attributes"""
        super(ASAObjGroupNetwork, self).__init__(*args, **kwargs)

        # Main diff with current code: Additional .+ to catch specific cases.
        self.name = self.re_match_typed(r'^object-group\snetwork\s+(\S.+)$',
            result_type=str, default='')

    @classmethod
    def is_object_for(cls, line="", re=re):
        if re.search(r'^(?:object-group\snetwork)', line):
            return True
        return False

    @property
    def description(self):
        regex = r"(^\s+description(?P<description0>.+)$)"
        retval = self.re_match_iter_typed(regex,
            result_type=str, default='')
        return retval

    def m_network_name_exist(self, name):
        group_ports = self.confobj.object_group_network.get(name, None) \
                or self.confobj.object_network.get(name, None)
                
        if name==self.name:
            ## Throw an error when importing self
            raise ValueError('FATAL: Cannot recurse through group-object {0}'\
                             ' in object-group or object network {1}'\
                             .format(name, self.name))
        if (group_ports is None):
            return False
        return True

    @property
    def result_dict(self):
        """Return a list of objects which represent 
        the network group members"""     
        retval = list()
        for obj in self.children:
            mm = _RE_ASA_NETOBJECT.search(obj.text)
            if not (mm is None):
                mm_r = mm.groupdict()
            else:
                raise ValueError("[FATAL] models_asa cannot parse '{0}'"\
                                 .format(obj.text))
            
            net_obj = dict()
            if mm_r.get('description0',None):
                net_obj['member_method'] = 'description'
            elif mm_r.get('host', None):
                net_obj['ipaddr'] = mm_r['host']
                net_obj['mask'] = '255.255.255.255'
                net_obj['member_method'] = 'host'
            elif mm_r.get('network', None):
                net_obj['subnet'] = mm_r['network']
                net_obj['mask'] = mm_r['netmask']
                net_obj['member_method'] = 'subnet'
            elif mm_r.get('group-object', None):
                net_obj['object_name'] = mm_r['groupobject']
                net_obj['member_method'] = 'group-object'
                # Make sure the network group was defined before
                if not self.m_network_name_exist(mm_r['groupobject']):
                    raise ValueError("FATAL: Cannot find network object named {0}"\
                                     .format(name))
            elif mm_r.get('object', None):
                net_obj['object_name'] = mm_r['object']
                net_obj['member_method'] = 'object'
                # Make sure the network object was defined before
                if not self.m_network_name_exist(mm_r['object']):
                    raise ValueError("FATAL: Cannot find network object named {0}"\
                                     .format(name))
            retval.append(net_obj)

        return retval

##
##-------------  ASA ACL object
##
## This class already exist in ciscoconfparse but I have rewrite it for 
## convenience and delivery delay.
## TODO: Extend the class instead of rewriting it.
##
_RE_ASA_ACL_STR = r"""(?:                         # Non-capturing parenthesis
# remark
(^access-list\s+(?P<name0>\S+)\s+(?P<type0>remark)\s+(?P<remark>.*)$)

# extended service object with source network object, destination network object
|(?:^access-list\s+(?P<name1>\S+)
 \s+(?P<type1>extended)
 \s+(?P<action1>permit|deny)
 \s+(?:                        # proto
     (?:object-group\s+(?P<service_objectgroup1>\S+))
    |(?:object\s+(?P<service_object1>\S+))
    |(?P<protocol1>{0})
 )
 \s+(?:                        # source addr
    (?P<src_any1>any|any4|any6)
    |(?:object-group\s+(?P<src_objectgroup1>\S+))
    |(?:object\s+(?P<src_object1>\S+))
    |(?:host\s+(?P<src_host1a>\S+))
    |(?:(?P<src_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<src_network1>\S+)\s+(?P<src_hostmask1>\d+\.\d+\.\d+\.\d+))
 )
 \s+(?:                       # destination addr
    (?P<dst_any1>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup1>\S+))
    |(?:object\s+(?P<dst_object1>\S+))
    |(?:host\s+(?P<dst_host1a>\S+))
    |(?:(?P<dst_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_network1>\S+)\s+(?P<dst_hostmask1>\d+\.\d+\.\d+\.\d+))
 )
 (?:\s+
   (?:                         # destination port
     (?:
        (?P<dst_port_op1>eq|neq|lt|gt)
        \s(?P<dst_port1>(?:(?:{3})\s?)+)
     )
     |(?:range\s+(?P<dst_port_low1>\S+)\s+(?P<dst_port_high1>\S+))
     |(?:object-group\s+(?P<dst_service_group1>\S+))
   )
 )?
 (?:\s+
    (?P<log1>log)
    (?:\s+(?P<loglevel1>{1}))?
    (?:\s+interval\s+(?P<log_interval1>\d+))?
 )?
 (?:\s+(?P<disable1>disable))?
 (?:
   (?:\s+(?P<inactive1>inactive))
   |(?:\s+time-range\s+(?P<time_range1>\S+))
 )?
\s*$)    # END access-list 1 parse

#access-list TESTME extended permit icmp any4 0.0.0.0 0.0.0.0 unreachable log interval 1
|(?:^access-list\s+(?P<name2>\S+)
 \s+(?P<type2>extended)
 \s+(?P<action2>permit|deny)
 \s+(?P<protocol2>icmp)
 \s+(?:                        # source addr
    (?P<src_any2>any|any4|any6)
    |(?:object-group\s+(?P<src_objectgroup2>\S+))
    |(?:object\s+(?P<src_object2>\S+))
    |(?:host\s+(?P<src_host2a>\S+))
    |(?:(?P<src_host2b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<src_network2>\S+)\s+(?P<src_hostmask2>\d+\.\d+\.\d+\.\d+))
 )
 \s+(?:                       # destination addr
    (?P<dst_any2>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup2>\S+))
    |(?:object\s+(?P<dst_object2>\S+))
    |(?:host\s+(?P<dst_host2a>\S+))
    |(?:(?P<dst_host2b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_network2>\S+)\s+(?P<dst_hostmask2>\d+\.\d+\.\d+\.\d+))
 )
 (?:\s+(?P<icmp_proto2>{3}|\d+))?
 (?:\s+
    (?P<log2>log)
    (?:\s+(?P<loglevel2>{1}))?
    (?:\s+interval\s+(?P<log_interval2>\d+))?
 )?
 (?:\s+(?P<disable2>disable))?
 (?:
    (?:\s+(?P<inactive2>inactive))
   |(?:\s+time-range\s+(?P<time_range2>\S+))
 )?
)

# access-list SPLIT_TUNNEL_NETS standard permit 192.0.2.0 255.255.255.0
|(?:^access-list\s+(?P<name3>\S+)
 \s+(?P<type3>standard)
 \s+(?P<action3>permit|deny)
 \s+(?:                       # destination addr
    (?P<dst_any3>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup3>\S+))
    |(?:object\s+(?P<dst_object3>\S+))
    |(?:host\s+(?P<dst_host3a>\S+))
    |(?:(?P<dst_host3b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_host3c>\S+))
    |(?:(?P<dst_network3>\S+)\s+(?P<dst_hostmask3>\d+\.\d+\.\d+\.\d+))
 )
 (?:\s+
    (?P<log3>log)
    (?:\s+(?P<loglevel3>{2}))?
    (?:\s+interval\s+(?P<log_interval3>\d+))?
 )?
 (?:\s+(?P<disable3>disable))?
 (?:
    (?:\s+(?P<inactive3>inactive))
   |(?:\s+time-range\s+(?P<time_range3>\S+))
 )?
)
)                                                   # Close non-capture parens
""".format(_ACL_PROTOCOLS, _ACL_LOGLEVELS, _ACL_ICMP_PROTOCOLS, _PORT_NAMES)
_RE_ASA_ACL = re.compile(_RE_ASA_ACL_STR, re.VERBOSE)

class ASAAclLine(models_asa.ASACfgLine):

    def __init__(self, *args, **kwargs):
        """Provide attributes on Cisco ASA Access-Lists"""
        super(ASAAclLine, self).__init__(*args, **kwargs)
        mm = _RE_ASA_ACL.search(self.text)
        if not (mm is None):
            self._mm_results = mm.groupdict()   # All regex match results
        else:
            raise ValueError("[FATAL] models_asa cannot parse '{0}'".format(self.text))

    @classmethod
    def is_object_for(cls, line="", re=re):
        if re.search('^access-list', line):
            return True
        return False

    @property
    def name(self):
        mm_r = self._mm_results
        return mm_r['name0'] or mm_r['name1'] or mm_r['name2'] \
                or mm_r['name3']

    @property
    def type(self):
        mm_r = self._mm_results
        return mm_r['type0'] or mm_r['type1'] or mm_r['type2'] or mm_r['type3']

    @property
    def action(self):
        mm_r = self._mm_results
        return mm_r['action1'] or mm_r['action2'] or mm_r['action3']

    @property
    def remark(self):
        mm_r = self._mm_results
        return mm_r['remark']

    @property
    def proto(self):
        mm_r = self._mm_results
        return mm_r['service_objectgroup1'] or mm_r['service_object1'] \
                or mm_r['protocol1'] or mm_r['protocol2']

    @property
    def proto_method(self):
        mm_r = self._mm_results
        if mm_r['protocol1'] or mm_r['protocol2']:
            return 'proto'
        elif mm_r['service_objectgroup1'] or mm_r['service_object1']:
            return 'object-group'
        elif self.action == 'remark':
            return 'remark'

    @property
    def src_addr(self):
        mm_r = self._mm_results
        return mm_r['src_any1'] or mm_r['src_objectgroup1'] \
                or mm_r['src_object1'] or mm_r['src_host1a'] \
                or mm_r['src_host1b'] \
                or mm_r['src_network1'] \
                \
                or mm_r['src_any2'] or mm_r['src_objectgroup2'] \
                or mm_r['src_object2'] or mm_r['src_host2a'] \
                or mm_r['src_host2b'] \
                or mm_r['src_network2']

    @property
    def src_hostmask(self):
        mm_r = self._mm_results
        method = self.src_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return  mm_r['src_hostmask1'] or mm_r['src_hostmask2']
        elif method == 'object-group' or method == 'object' \
                or method == 'remark' \
                or self.parent.type == 'standard': # standard acl = no src ip
            return None

    @property
    def src_addr_method(self):
        mm_r = self._mm_results
        if mm_r['src_any1'] or mm_r['src_any2']:
            return 'any'
        elif mm_r['src_objectgroup1'] or mm_r['src_objectgroup2']:
            return 'object-group'
        elif mm_r['src_object1'] or mm_r['src_object2']:
            return 'object'
        elif mm_r['src_host1a'] or mm_r['src_host1b'] \
                or mm_r['src_host2a'] or mm_r['src_host2b']:
            return 'host'
        elif (mm_r['src_network1'] or mm_r['src_hostmask1']) \
                or (mm_r['src_network2'] or mm_r['src_hostmask2']):
            return 'network'
        elif self.action == 'remark':
            return 'remark'
        elif self.parent.type == 'standard':    # standard acl = no src ip
            return None

    @property
    def src_port(self):
        return None

    @property
    def src_port_method(self):
        return None

    @property
    def dst_addr(self):
        mm_r = self._mm_results
        return mm_r['dst_any1'] or mm_r['dst_objectgroup1'] \
                or mm_r['dst_object1'] or mm_r['dst_host1a'] \
                or mm_r['dst_host1b'] \
                or mm_r['dst_network1'] \
                \
                or mm_r['dst_any2'] or mm_r['dst_objectgroup2'] \
                or mm_r['dst_object2'] or mm_r['dst_host2a'] \
                or mm_r['dst_host2b'] \
                or mm_r['dst_network2'] \
                \
                or mm_r['dst_any3'] or mm_r['dst_objectgroup3'] \
                or mm_r['dst_object3'] or mm_r['dst_host3a'] \
                or mm_r['dst_host3b'] or mm_r['dst_host3c']\
                or mm_r['dst_network3']

    @property
    def dst_hostmask(self):
        mm_r = self._mm_results
        method = self.dst_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return mm_r['dst_hostmask1'] or mm_r['dst_hostmask2'] \
                    or mm_r['dst_hostmask3']
        elif method == 'object-group' or method == 'object' \
                or method == 'remark':
            return None
        else:
            return None

    @property
    def dst_addr_method(self):
        mm_r = self._mm_results
        if mm_r['dst_any1'] or mm_r['dst_any2'] or mm_r['dst_any3']:
            return 'any'
        elif mm_r['dst_objectgroup1'] or mm_r['dst_objectgroup2'] \
                or mm_r['dst_objectgroup3']:
            return 'object-group'
        elif mm_r['dst_object1'] or mm_r['dst_object2'] or mm_r['dst_object3']:
            return 'object'
        elif mm_r['dst_host1a'] or mm_r['dst_host1b'] \
                or mm_r['dst_host2a'] or mm_r['dst_host2b'] \
                or mm_r['dst_host3a'] or mm_r['dst_host3b'] \
                or mm_r['dst_host3c']:
            return 'host'
        elif (mm_r['dst_network1'] and mm_r['dst_hostmask1']) \
                or (mm_r['dst_network2'] and mm_r['dst_hostmask2']) \
                or (mm_r['dst_network3'] and mm_r['dst_hostmask3']):
            return 'network'
        elif self.action == 'remark':
            return 'remark'
        else:
            return None

    @property
    def dst_port(self):
        mm_r = self._mm_results
        if self.dst_port_method == 'range':
            return mm_r['dst_port_low1'] + ' ' + mm_r['dst_port_high1']
        return mm_r['dst_port1'] or mm_r['dst_service_group1']

    @property
    def dst_port_method(self):
        mm_r = self._mm_results
        if mm_r['dst_port_op1']:
            return mm_r['dst_port_op1']
        elif mm_r['dst_port_low1'] and mm_r['dst_port_high1']:
            return 'range'
        elif mm_r['dst_service_group1']:
            return 'object-group'

    @property
    def log(self):
        mm_r = self._mm_results
        return mm_r['log1'] or mm_r['log2']

    @property
    def log_level(self):
        mm_r = self._mm_results
        return mm_r['log_level1'] or mm_r['log_level2']

    @property
    def log_interval(self):
        mm_r = self._mm_results
        return mm_r['log_interval1'] or mm_r['log_interval2']

    @property
    def disable(self):
        mm_r = self._mm_results
        return mm_r['disable1'] or mm_r['disable2']

    @property
    def inactive(self):
        mm_r = self._mm_results
        return mm_r['inactive1'] or mm_r['inactive2']

    @property
    def time_range(self):
        mm_r = self._mm_results
        return mm_r['time_range1'] or mm_r['time_range2']

    # TODO: This should not be needed
    # Otherwise: fix code to support this attribute.
    @property
    def established(self):
        mm_r = self._mm_results
        return mm_r['established']

class ASAConfigList(ccp.ASAConfigList):
    def __init__(self, data=None, comment_delimiter='!', debug=False, 
        factory=False, ignore_blank_lines=True, syntax='asa', CiscoConfParse=None):
        super(ASAConfigList, self).__init__(data, comment_delimiter, debug, factory, \
                                   ignore_blank_lines, syntax, CiscoConfParse)

        ### New Internal structures
        self._RE_NETS  = re.compile(r'^\s*object\s+network\s+(\S+)')
        self._RE_SVCS  = re.compile(r'^\s*object\s+service\s+(\S+)')

    @property
    def object_network(self):
        """Return a dictionary of name to object network mappings"""
        retval = dict()
        obj_rgx = self._RE_NETS
        for obj in self.CiscoConfParse.find_objects(obj_rgx):
            name = obj.re_match_typed(obj_rgx, group=1, result_type=str)
            retval[name] = obj
        return retval

    @property
    def object_service(self):
        """Return a dictionary of name to object network mappings"""
        retval = dict()
        obj_rgx = self._RE_SVCS
        for obj in self.CiscoConfParse.find_objects(obj_rgx):
            name = obj.re_match_typed(obj_rgx, group=1, result_type=str)
            retval[name] = obj
        return retval

    @property
    def object_group_service(self):
        """Return a dictionary of name to object-group service mappings"""
        retval = dict()
        obj_rgx = self._RE_OBJSVC
        for obj in self.CiscoConfParse.find_objects(obj_rgx):
            name = obj.re_match_typed(obj_rgx, group=1, result_type=str)
            retval[name] = obj
        return retval

##
##-------------  IOS ACL object
##
_RE_IOS_ACL_STR = r"""(?:                         # Non-capturing parenthesis
# basic access-list
# access-list 10 permet 1.2.3.4 0.0.15.255
(?:^access-list\s+(?P<acl_num0>\S+)
  \s+(?P<action0>permit|deny)
  \s+(?:                       # 10.0.0.0 255.255.255.0
    (?P<dst_any0>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup0>\S+))
    |(?:object\s+(?P<dst_object0>\S+))
    |(?:host\s+(?P<dst_host0a>\S+))
    |(?:(?P<dst_host0b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_host0c>\S+))
    |(?:(?P<dst_network0>\S+)\s+(?P<dst_hostmask0>\d+\.\d+\.\d+\.\d+))
  )
  (?:\s+
    (?P<log0>log)
    (?:\s+(?P<log_level0>{1}))?
    (?:\s+interval\s+(?P<log_interval0>\d+))?
  )?
  (?:\s+(?P<disable0>disable))?
  (?:
    (?:\s+(?P<inactive0>inactive))
   |(?:\s+time-range\s+(?P<time_range0>\S+))
  )?
 \s*$)    # END access-list 0 parse

# extended access-list 
# access-list 100 permit ip any host 10.1.2.3
|(?:^access-list\s+(?P<acl_num1>\S+)
  \s+(?P<action1>permit|deny)
  \s+(?:
     (?:object-group\s+(?P<service_object1>\S+))
    |(?P<protocol1>{0})
  )
  \s+(?:                       # 10.0.0.0 255.255.255.0
    (?P<src_any1>any|any4|any6)
    |(?:object-group\s+(?P<src_objectgroup1>\S+))
    |(?:object\s+(?P<src_object1>\S+))
    |(?:host\s+(?P<src_host1a>\S+))
    |(?:(?P<src_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<src_network1>\S+)\s+(?P<src_hostmask1>\d+\.\d+\.\d+\.\d+))
  )
  \s+(?:                       # 10.0.0.0 255.255.255.0
    (?P<dst_any1>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup1>\S+))
    |(?:object\s+(?P<dst_object1>\S+))
    |(?:host\s+(?P<dst_host1a>\S+))
    |(?:(?P<dst_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_network1>\S+)\s+(?P<dst_hostmask1>\d+\.\d+\.\d+\.\d+))
  )
  (?:\s+
    (?P<log1>log)
    (?:\s+(?P<log_level1>{1}))?
    (?:\s+interval\s+(?P<log_interval1>\d+))?
  )?
  (?:\s+(?P<disable1>disable))?
  (?:
    (?:\s+(?P<inactive1>inactive))
   |(?:\s+time-range\s+(?P<time_range1>\S+))
  )?
 \s*$)    # END access-list 1 parse
)
""".format(_ACL_PROTOCOLS, _ACL_LOGLEVELS, _ACL_ICMP_PROTOCOLS)
_RE_IOS_ACL = re.compile(_RE_IOS_ACL_STR, re.VERBOSE)

class IOSAclLine(models_cisco.BaseCfgLine):
    def __init__(self, *args, **kwargs):
        """Provide attributes on Cisco IOS Access-Lists"""
        super(IOSAclLine, self).__init__(*args, **kwargs)
        mm = _RE_IOS_ACL.search(self.text)
        if not (mm is None):
            self._mm_results = mm.groupdict()   # All regex match results
        else:
            raise ValueError("[FATAL] models_cisco cannot parse '{0}'".format(self.text))
    
    def __repr__(self):
        return "<%s # %s '%s'>" % (self.classname, self.linenum, self.name)

    @classmethod
    def is_object_for(cls, line="", re=re):
        if 'access-list ' in line[0:13].lower():
            return True
        return False

    @property
    def name(self):
        mm_r = self._mm_results
        return mm_r['acl_num0'] or mm_r['acl_num1']

    @property
    def action(self):
        mm_r = self._mm_results
        return mm_r['action0'] or mm_r['action1']

    @property
    def type(self):
        mm_r = self._mm_results
        if mm_r['action0']:
            return 'standard'
        elif mm_r['action1']:
            return 'extended'

    @property
    def proto(self):
        mm_r = self._mm_results
        return mm_r['service_object1'] or mm_r['protocol1']

    @property
    def proto_method(self):
        mm_r = self._mm_results
        if mm_r['service_object1']:
            return 'object-group'
        elif mm_r['protocol1']:
            return 'proto'

    @property
    def src_addr(self):
        mm_r = self._mm_results
        return mm_r['src_any1'] or mm_r['src_objectgroup1'] \
                or mm_r['src_object1'] or mm_r['src_host1a'] \
                or mm_r['src_host1b'] \
                or mm_r['src_network1']

    @property
    def src_hostmask(self):
        mm_r = self._mm_results
        method = self.src_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return mm_r['src_hostmask1']
        elif method == 'object-group' or method == 'object':
            return None
        else:
            return None
            #raise ValueError("Cannot parse ACL source hostmask for '{0}'".format(self.text))

    @property
    def src_addr_method(self):
        mm_r = self._mm_results
        if mm_r['src_any1']:
            return 'any'
        elif mm_r['src_objectgroup1']:
            return 'object-group'
        elif mm_r['src_object1']:
            return 'object'
        elif mm_r['src_host1a'] or mm_r['src_host1b']:
            return 'host'
        elif (mm_r['src_network1'] or mm_r['src_hostmask1']):
            return 'network'
        else:
            return None
            #raise ValueError("Cannot parse ACL source address method for '{0}'".format(self.text))

    @property
    def dst_addr(self):
        mm_r = self._mm_results
        return mm_r['dst_any0'] or mm_r['dst_objectgroup0'] \
                or mm_r['dst_object0'] or mm_r['dst_host0a'] \
                or mm_r['dst_host0b'] \
                or mm_r['dst_network0'] \
                \
                or mm_r['dst_any1'] or mm_r['dst_objectgroup1'] \
                or mm_r['dst_object1'] or mm_r['dst_host1a'] \
                or mm_r['dst_host1b'] \
                or mm_r['dst_network1']

    @property
    def dst_hostmask(self):
        mm_r = self._mm_results
        method = self.dst_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return mm_r['dst_hostmask0'] or mm_r['dst_hostmask1']
        elif method == 'object-group' or method == 'object':
            return None
        else:
            return None

    @property
    def dst_addr_method(self):
        mm_r = self._mm_results
        if mm_r['dst_any0'] or mm_r['dst_any1']:
            return 'any'
        elif mm_r['dst_objectgroup0'] or mm_r['dst_objectgroup1']:
            return 'object-group'
        elif mm_r['dst_object0'] or mm_r['dst_object1']:
            return 'object'
        elif mm_r['dst_host0a'] or mm_r['dst_host0b']\
            or mm_r['dst_host1a'] or mm_r['dst_host1b']:
            return 'host'
        elif (mm_r['dst_network0'] and mm_r['dst_hostmask0'])\
            or (mm_r['dst_network1'] and mm_r['dst_hostmask1']):
            return 'network'
        else:
            return None

    @property
    def log(self):
        mm_r = self._mm_results
        return mm_r['log0'] or mm_r['log1']

    @property
    def log_level(self):
        mm_r = self._mm_results
        return mm_r['log_level0'] or mm_r['log_level1']

    @property
    def log_interval(self):
        mm_r = self._mm_results
        return mm_r['log_interval0'] or mm_r['log_interval1']

    @property
    def disable(self):
        mm_r = self._mm_results
        return mm_r['disable0'] or mm_r['disable1']

    @property
    def inactive(self):
        mm_r = self._mm_results
        return mm_r['inactive0'] or mm_r['inactive1']

    @property
    def time_range(self):
        mm_r = self._mm_results
        return mm_r['time_range0'] or mm_r['time_range1']

    @property
    def result_dict(self):
        mm_r = self._mm_results
        retval = dict()

        proto_dict = self.acl_protocol_dict
        retval['ip_protocol'] = proto_dict['protocol']
        retval['ip_protocol_object'] = proto_dict['protocol_object']
        retval['acl_name'] = mm_r['acl_name0'] or mm_r['acl_name1'] \
            or mm_r['acl_name2'] or mm_r['acl_name3'] or mm_r['acl_name4']
        retval['action'] = mm_r['action0'] or mm_r['action1'] \
            or mm_r['action2'] or mm_r['action3'] or mm_r['action4']
        retval['remark'] = mm_r['remark']
        retval['src_addr_method'] = self.src_addr_method
        retval['dst_addr_method'] = self.dst_addr_method
        retval['disable'] = bool(mm_r['disable1'] or mm_r['disable2'] or mm_r['disable4'])
        retval['time_range'] = mm_r['time_range1'] or mm_r['time_range2'] or mm_r['time_range4']
        retval['log'] = bool(mm_r['log1'] or mm_r['log2'] or mm_r['log4'])
        if not retval['log']:
            retval['log_interval'] = -1
            retval['log_level'] = ''
        else:
            retval['log_level'] = mm_r['log_level1'] or mm_r['log_level2'] or mm_r['log_level4'] or 'informational'
            retval['log_interval'] = int(mm_r['log_interval1'] \
                or mm_r['log_interval2'] or mm_r['log_interval4'] or 300)

        return retval

_RE_IOS_IPACL_STR = r"""(?:                    # Non-capturing parenthesis
 (^ip\s+access-list\s+(?P<type>standard|extended)\s+(?P<name>\S+)$)
)                                                # Close non-capture parens
"""
_RE_IOS_IPACL = re.compile(_RE_IOS_IPACL_STR, re.VERBOSE)

##
## ------------- IOS "ip access-list" objects
##
class IOSIPAclLine(models_cisco.BaseCfgLine):
    def __init__(self, *args, **kwargs):
        """
        """
        """Provide attributes on Cisco IOS Access-Lists"""
        super(IOSIPAclLine, self).__init__(*args, **kwargs)
        mm = _RE_IOS_IPACL.search(self.text)
        if not (mm is None):
            self._mm_results = mm.groupdict()   # All regex match results
        else:
            raise ValueError("[FATAL] models_cisco cannot parse '{0}'".format(self.text))
    
    def __repr__(self):
        return "<%s # %s '%s'>" % (self.classname, self.linenum, self.name)

    @classmethod
    def is_object_for(cls, line="", re=re):
        if 'ip access-list ' in line[0:16].lower():
            return True
        return False

    @property
    def name(self):
        mm_r = self._mm_results
        return mm_r['name']

    @property
    def type(self):
        mm_r = self._mm_results
        return mm_r['type']

##
## ------------- IOS child of "ip access-list" objects
##
_RE_IOS_IPACL_CHILD_STR = r"""(?:           # Non-capturing parenthesis
# remark
 (^\s+(?P<action0>remark)\s+(?P<remark>\S.+?)$)

# extended service object with protocol, source network object, 
# destination network object
# permit ip host 10.112.143.212 any
# permit ip host 10.111.143.201 host 10.112.191.101 log
# permit udp 172.18.0.0 0.0.255.255 host 10.112.191.251 eq domain ntp 389
# permit tcp 192.168.1.240 0.0.0.15 host 172.19.33.11 range 20000 20010
|(^\s+(?P<action1>permit|deny)
  \s+(?:
     (?:object-group\s+(?P<service_object1>\S+))
    |(?P<protocol1>{0})
  )
  \s+(?:                        # source addr
    (?P<src_any1>any|any4|any6)
    |(?:object-group\s+(?P<src_objectgroup1>\S+))
    |(?:object\s+(?P<src_object1>\S+))
    |(?:host\s+(?P<src_host1a>\S+))
    |(?:(?P<src_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<src_network1>\S+)\s+(?P<src_hostmask1>\d+\.\d+\.\d+\.\d+))
  )
  (?:\s+
    (?:                         # source port
      (?:
        (?P<src_port_op1>eq|neq|lt|gt)
        \s(?P<src_port1>(?:(?:{3})\s?)+)
      )
      |(?:range\s+(?P<src_port_low1>\S+)\s+(?P<src_port_high1>\S+))
      |(?:object-group\s+(?P<src_service_object1>\S+))
    )
  )?
  \s+(?:                       # destination addr
    (?P<dst_any1>any|any4|any6)
    |(?:object-group\s+(?P<dst_objectgroup1>\S+))
    |(?:object\s+(?P<dst_object1>\S+))
    |(?:host\s+(?P<dst_host1a>\S+))
    |(?:(?P<dst_host1b>\S+)\s+0\.0\.0\.0)
    |(?:(?P<dst_network1>\S+)\s+(?P<dst_hostmask1>\d+\.\d+\.\d+\.\d+))
  )
  (?:\s+
    (?:                         # destination port
      (?:
        (?P<dst_port_op1>eq|neq|lt|gt)
        \s(?P<dst_port1>(?:(?:{3})\s?)+)
      )
      |(?:range\s+(?P<dst_port_low1>\S+)\s+(?P<dst_port_high1>\S+))
      |(?:object-group\s+(?P<dst_service_object1>\S+))
    )
  )?
  (?:\s+
    (?P<log1>log)
    (?:\s+(?P<log_level1>{1}))?
    (?:\s+interval\s+(?P<log_interval1>\d+))?
  )?
  (?:\s+(?P<disable1>disable))?
  (?:
    (?:\s+(?P<inactive1>inactive))
   |(?:\s+time-range\s+(?P<time_range1>\S+))
  )?
  (?:\s+(?P<established>established))?     # established = temporary hack.
 \s*$)    # END access-list 1 parse

# ICMP
# permit icmp any4 0.0.0.0 0.0.0.0 unreachable log interval 1
# permit icmp object-group ISO_NET host 172.19.33.11
|(^\s+(?P<action2>permit|deny)
  \s+(?P<protocol2>icmp)
  (?:\s+       # source addr
    (?:
      (?P<src_any2>any|any4|any6)
      |(?:object-group\s+(?P<src_objectgroup2>\S+))
      |(?:object\s+(?P<src_object2>\S+))
      |(?:host\s+(?P<src_host2a>\S+))
      |(?:(?P<src_host2b>\S+)\s+0\.0\.0\.0)
      |(?:(?P<src_network2>\S+)\s+(?P<src_hostmask2>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+       # destination addr
     (?:
      (?P<dst_any2>any|any4|any6)
      |(?:object-group\s+(?P<dst_objectgroup2>\S+))
      |(?:object\s+(?P<dst_object2>\S+))
      |(?:host\s+(?P<dst_host2a>\S+))
      |(?:(?P<dst_host2b>\S+)\s+0\.0\.0\.0)
      |(?:(?P<dst_network2>\S+)\s+(?P<dst_hostmask2>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+(?P<icmp_proto2>{2}|\d+))?
  (?:\s+
    (?P<log2>log)
    (?:\s+(?P<log_level2>{1}))?
    (?:\s+interval\s+(?P<log_interval2>\d+))?
  )?
  (?:\s+(?P<disable2>disable))?
  (?:
    (?:\s+(?P<inactive2>inactive))
   |(?:\s+time-range\s+(?P<time_range2>\S+))
  )?
 \s*$)

# For standard ACLs
#ip access-list standard ALLOW_MOD_OSPF_AD
# permit 10.0.0.0 0.255.255.255
|(^\s+(?P<action3>permit|deny)
  (?:\s+       # destination addr
    (?:
      (?P<dst_any3>any|any4|any6|0\.0\.0\.0)
      |(?:object-group\s+(?P<dst_objectgroup3>\S+))
      |(?:object\s+(?P<dst_object3>\S+))
      |(?:host\s+(?P<dst_host3a>\S+))
      |(?:(?P<dst_host3b>\S+)\s+0\.0\.0\.0)
      |(?:(?P<dst_host3c>\S+))
      |(?:(?P<dst_network3>\S+)\s+(?P<dst_hostmask3>\d+\.\d+\.\d+\.\d+))
    )
  )
 \s*$)
)                                         # Close non-capture parens
""".format(_ACL_PROTOCOLS, _ACL_LOGLEVELS, _ACL_ICMP_PROTOCOLS, _PORT_NAMES)
_RE_IOS_IPACL_CHILD = re.compile(_RE_IOS_IPACL_CHILD_STR, re.VERBOSE)

class IOSIPAclChildLine(models_cisco.BaseCfgLine):
    def __init__(self, *args, **kwargs):
        """Provide attributes on Cisco IOS Access-Lists"""
        super(IOSIPAclChildLine, self).__init__(*args, **kwargs)
        mm = _RE_IOS_IPACL_CHILD.search(self.text)
        if not (mm is None):
            self._mm_results = mm.groupdict()   # All regex match results
        else:
            raise ValueError("[FATAL] models_cisco cannot parse '{0}'".format(self.text))
    
    def __repr__(self):
        return "<%s # %s '%s'>" % (self.classname, self.linenum, self.text)

    @classmethod
    def is_object_for(cls, line="", re=re):
        aclChild_regex = r'^\s+remark|permit|deny\s+(\S+.+)$'
        if re.search(aclChild_regex, line):
            return True
        return False

    @property
    def name(self):
        return self.parent.name

    @property
    def action(self):
        mm_r = self._mm_results
        return mm_r['action0'] or mm_r['action1'] or mm_r['action2'] \
                or mm_r['action3']

    @property
    def remark(self):
        mm_r = self._mm_results
        return mm_r['remark']

    @property
    def proto(self):
        mm_r = self._mm_results
        return mm_r['service_object1'] \
                or mm_r['protocol1'] or mm_r['protocol2']

    @property
    def proto_method(self):
        mm_r = self._mm_results
        if mm_r['protocol1'] or mm_r['protocol2']:
            return 'proto'
        elif mm_r['service_object1']:
            return 'object-group'
        elif self.action == 'remark':
            return 'remark'

    @property
    def src_addr(self):
        mm_r = self._mm_results
        return mm_r['src_any1'] or mm_r['src_objectgroup1'] \
                or mm_r['src_object1'] or mm_r['src_host1a'] \
                or mm_r['src_host1b'] \
                or mm_r['src_network1'] \
                \
                or mm_r['src_any2'] or mm_r['src_objectgroup2'] \
                or mm_r['src_object2'] or mm_r['src_host2a'] \
                or mm_r['src_host2b'] \
                or mm_r['src_network2']

    @property
    def src_hostmask(self):
        mm_r = self._mm_results
        method = self.src_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return  mm_r['src_hostmask1'] or mm_r['src_hostmask2']
        elif method == 'object-group' or method == 'object' \
                or method == 'remark' \
                or self.parent.type == 'standard': # standard acl = no src ip
            return None

    @property
    def src_addr_method(self):
        mm_r = self._mm_results
        if mm_r['src_any1'] or mm_r['src_any2']:
            return 'any'
        elif mm_r['src_objectgroup1'] or mm_r['src_objectgroup2']:
            return 'object-group'
        elif mm_r['src_object1'] or mm_r['src_object2']:
            return 'object'
        elif mm_r['src_host1a'] or mm_r['src_host1b'] \
                or mm_r['src_host2a'] or mm_r['src_host2b']:
            return 'host'
        elif (mm_r['src_network1'] or mm_r['src_hostmask1']) \
                or (mm_r['src_network2'] or mm_r['src_hostmask2']):
            return 'network'
        elif self.action == 'remark':
            return 'remark'
        elif self.parent.type == 'standard':    # standard acl = no src ip
            return None

    @property
    def src_port(self):
        mm_r = self._mm_results
        if self.src_port_method == 'range':
            return mm_r['src_port_low1'] + ' ' + mm_r['src_port_high1']
        return mm_r['src_port1'] or mm_r['src_service_object1']

    @property
    def src_port_method(self):
        mm_r = self._mm_results
        if mm_r['src_port_op1']:
            return mm_r['src_port_op1']
        elif mm_r['src_port_low1'] and mm_r['src_port_high1']:
            return 'range'
        elif mm_r['src_service_object1']:
            return 'object-group'

    @property
    def dst_addr(self):
        mm_r = self._mm_results
        return mm_r['dst_any1'] or mm_r['dst_objectgroup1'] \
                or mm_r['dst_object1'] or mm_r['dst_host1a'] \
                or mm_r['dst_host1b'] \
                or mm_r['dst_network1'] \
                \
                or mm_r['dst_any2'] or mm_r['dst_objectgroup2'] \
                or mm_r['dst_object2'] or mm_r['dst_host2a'] \
                or mm_r['dst_host2b'] \
                or mm_r['dst_network2'] \
                \
                or mm_r['dst_any3'] or mm_r['dst_objectgroup3'] \
                or mm_r['dst_object3'] or mm_r['dst_host3a'] \
                or mm_r['dst_host3b'] or mm_r['dst_host3c']\
                or mm_r['dst_network3']

    @property
    def dst_hostmask(self):
        mm_r = self._mm_results
        method = self.dst_addr_method
        if method == 'any':
            return '255.255.255.255'
        elif method == 'host':
            return '0.0.0.0'
        elif method == 'network':
            return mm_r['dst_hostmask1'] or mm_r['dst_hostmask2'] \
                    or mm_r['dst_hostmask3']
        elif method == 'object-group' or method == 'object' \
                or method == 'remark':
            return None
        else:
            return None

    @property
    def dst_addr_method(self):
        mm_r = self._mm_results
        if mm_r['dst_any1'] or mm_r['dst_any2'] or mm_r['dst_any3']:
            return 'any'
        elif mm_r['dst_objectgroup1'] or mm_r['dst_objectgroup2'] \
                or mm_r['dst_objectgroup3']:
            return 'object-group'
        elif mm_r['dst_object1'] or mm_r['dst_object2'] or mm_r['dst_object3']:
            return 'object'
        elif mm_r['dst_host1a'] or mm_r['dst_host1b'] \
                or mm_r['dst_host2a'] or mm_r['dst_host2b'] \
                or mm_r['dst_host3a'] or mm_r['dst_host3b'] \
                or mm_r['dst_host3c']:
            return 'host'
        elif (mm_r['dst_network1'] and mm_r['dst_hostmask1']) \
                or (mm_r['dst_network2'] and mm_r['dst_hostmask2']) \
                or (mm_r['dst_network3'] and mm_r['dst_hostmask3']):
            return 'network'
        elif self.action == 'remark':
            return 'remark'
        else:
            return None

    @property
    def dst_port(self):
        mm_r = self._mm_results
        if self.dst_port_method == 'range':
            return mm_r['dst_port_low1'] + ' ' + mm_r['dst_port_high1']
        return mm_r['dst_port1'] or mm_r['dst_service_object1']

    @property
    def dst_port_method(self):
        mm_r = self._mm_results
        if mm_r['dst_port_op1']:
            return mm_r['dst_port_op1']
        elif mm_r['dst_port_low1'] and mm_r['dst_port_high1']:
            return 'range'
        elif mm_r['dst_service_object1']:
            return 'object-group'

    @property
    def log(self):
        mm_r = self._mm_results
        return mm_r['log1'] or mm_r['log2']

    @property
    def log_level(self):
        mm_r = self._mm_results
        return mm_r['log_level1'] or mm_r['log_level2']

    @property
    def log_interval(self):
        mm_r = self._mm_results
        return mm_r['log_interval1'] or mm_r['log_interval2']

    @property
    def disable(self):
        mm_r = self._mm_results
        return mm_r['disable1'] or mm_r['disable2']

    @property
    def inactive(self):
        mm_r = self._mm_results
        return mm_r['inactive1'] or mm_r['inactive2']

    @property
    def time_range(self):
        mm_r = self._mm_results
        return mm_r['time_range1'] or mm_r['time_range2']

    # TODO: This should not be needed
    # Otherwise: fix code to support this attribute.
    @property
    def established(self):
        mm_r = self._mm_results
        return mm_r['established']

##
## ----------------- New L4Object. 
## Features: New attributes: operator, port_spec, src_port_list
##
class L4Object(object):
    """Object for Transport-layer protocols; the object ensures that logical operators (such as le, gt, eq, and ne) are parsed correctly, as well as mapping service names to port numbers"""
    def __init__(self, protocol='', port_spec='', syntax=''):
        self.protocol = protocol
        self.operator = ''
        self.port_spec = port_spec
        self.port_list = list()
        self.src_port_list = list()
        self.syntax = syntax

        try:
            port_spec = port_spec.strip()
        except:
            port_spec = port_spec

        if syntax=='asa':
            if protocol=='tcp':
                ports = ASA_TCP_PORTS
            elif protocol=='udp':
                ports = ASA_UDP_PORTS
            else:
                raise NotImplementedError("'{0}' is not supported: '{0}'".format(protocol))
        else:
            raise NotImplementedError("This syntax is unknown: '{0}'".format(syntax))

        if 'eq ' in port_spec:
            port_str = re.split('\s+', port_spec)[-1]
            self.operator = 'eq'
            self.port_list = [int(ports.get(port_str, port_str))]
        elif re.search(r'^\S+$', port_spec):
            # Technically, 'eq ' is optional...
            self.operator = 'eq'
            self.port_list = [int(ports.get(port_spec, port_spec))]
        elif 'range ' in port_spec:
            port_tmp = re.split('\s+', port_spec)[1:]
            self.operator = 'range'
            self.port_list = range(int(ports.get(port_tmp[0], port_tmp[0])), 
                int(ports.get(port_tmp[1], port_tmp[1])) + 1)
        elif 'lt ' in port_spec:
            port_str = re.split('\s+', port_spec)[-1]
            self.operator = 'lt'
            self.port_list = range(1, int(ports.get(port_str, port_str)))
        elif 'gt ' in port_spec:
            port_str = re.split('\s+', port_spec)[-1]
            self.operator = 'gt'
            self.port_list = range(int(ports.get(port_str, port_str)) + 1, 65535)
        elif 'neq ' in port_spec:
            port_str = re.split('\s+', port_spec)[-1]
            tmp = set(range(1, 65535))
            tmp.remove(int(port_str))
            self.operator = 'neq'
            self.port_list = sorted(tmp)

    def __eq__(self, val):
        if (self.protocol==val.protocol) and (self.port_list==val.port_list):
            return True
        return False

    def __repr__(self):
        return "<L4Object {0} {1}>".format(self.protocol, self.port_list)

##
##------------- New ConfigLineFactory 
##
def ConfigLineFactory(text="", comment_delimiter="!", syntax='ios'):
    if syntax=='ios':
        classes = [models_cisco.IOSIntfLine, \
                  models_cisco.IOSRouteLine, \
                  models_cisco.IOSAccessLine, \
                  models_cisco.IOSAaaLoginAuthenticationLine, \
                  models_cisco.IOSAaaEnableAuthenticationLine, \
                  models_cisco.IOSAaaCommandsAuthorizationLine, \
                  models_cisco.IOSAaaCommandsAccountingLine, \
                  models_cisco.IOSAaaExecAccountingLine, \
                  models_cisco.IOSAaaGroupServerLine, \
                  models_cisco.IOSHostnameLine, \
                  models_cisco.IOSIntfGlobal, \
                  IOSAclLine, \
                  IOSIPAclLine, \
                  IOSIPAclChildLine, \
                  models_cisco.IOSCfgLine]
    elif syntax=='asa':
        classes = [models_asa.ASAName, \
                  ASAObjNetwork, \
                  ASAObjService, \
                  ASAObjGroupNetwork, \
                  ASAObjGroupService, \
                  ASAObjGroupProtocol, \
                  models_asa.ASAIntfLine, \
                  models_asa.ASAIntfGlobal, \
                  models_asa.ASAHostnameLine, \
                  ASAAclLine, \
                  models_asa.ASACfgLine]
    for cls in classes:
        if cls.is_object_for(text):
            inst = cls(text=text, 
                comment_delimiter=comment_delimiter) # instance of the proper subclass
            return inst
    raise ValueError("Could not find an object for '%s'" % line)

##
##------------- Monkey Patching
## Temporary patch. Goal is to send a pull request to the project.
##
ccp.ConfigLineFactory = ConfigLineFactory
models_asa.ASAConfigList = ASAConfigList

##
##------------- New CiscoConfParse definition
## Reason: Have a good reference to ASAConfigList
##
class CiscoConfParse(ccp.CiscoConfParse):
    """Parses Cisco IOS configurations and answers queries about the configs"""

    def __init__(self, config="", comment="!", debug=False, factory=False, 
        linesplit_rgx=r"\r*\n+", ignore_blank_lines=True, syntax='ios'):
        """
            You will find a great class description in ccp.CiscoConfParse
        """

        # all IOSCfgLine object instances...
        self.comment_delimiter = comment
        self.factory = factory
        self.ConfigObjs = None
        self.syntax = syntax
        self.debug = debug

        if isinstance(config, list) or isinstance(config, Iterator):
            if syntax=='ios':
                # we already have a list object, simply call the parser
                if self.debug:
                    _log.debug("parsing from a python list with ios syntax")
                self.ConfigObjs = ccp.IOSConfigList(data=config, 
                    comment_delimiter=comment, 
                    debug=debug, 
                    factory=factory, 
                    ignore_blank_lines=ignore_blank_lines,
                    syntax='ios',
                    CiscoConfParse=self)
            elif syntax=='asa':
                # we already have a list object, simply call the parser
                if self.debug:
                    _log.debug("parsing from a python list with asa syntax")
                self.ConfigObjs = ASAConfigList(data=config, 
                    comment_delimiter=comment, 
                    debug=debug, 
                    factory=factory, 
                    ignore_blank_lines=ignore_blank_lines,
                    syntax='asa',
                    CiscoConfParse=self)
            elif syntax=='junos':
                ## FIXME I am shamelessly abusing the IOSConfigList for now...
                # we already have a list object, simply call the parser
                config = self.convert_braces_to_ios(config)
                if self.debug:
                    _log.debug("parsing from a python list with junos syntax")
                self.ConfigObjs = ccp.IOSConfigList(data=config, 
                    comment_delimiter=comment, 
                    debug=debug, 
                    factory=factory, 
                    ignore_blank_lines=ignore_blank_lines,
                    syntax='junos',
                    CiscoConfParse=self)
            else:
                raise ValueError("FATAL: '{}' is an unknown syntax".format(syntax))

        ## Accept either a string or unicode...
        elif getattr(config, 'encode', False):
            # Try opening as a file
            try:
                if syntax=='ios':
                    # string - assume a filename... open file, split and parse
                    if self.debug:
                        _log.debug("parsing from '{0}' with ios syntax".format(config))
                    f = open(config, mode="rU")
                    text = f.read()
                    rgx = re.compile(linesplit_rgx)
                    self.ConfigObjs = ccp.IOSConfigList(rgx.split(text), 
                        comment_delimiter=comment, 
                        debug=debug,
                        factory=factory,
                        ignore_blank_lines=ignore_blank_lines,
                        syntax='ios',
                        CiscoConfParse=self)
                elif syntax=='asa':
                    # string - assume a filename... open file, split and parse
                    if self.debug:
                        _log.debug("parsing from '{0}' with asa syntax".format(config))
                    f = open(config, mode="rU")
                    text = f.read()
                    rgx = re.compile(linesplit_rgx)
                    self.ConfigObjs = ASAConfigList(rgx.split(text), 
                        comment_delimiter=comment, 
                        debug=debug,
                        factory=factory,
                        ignore_blank_lines=ignore_blank_lines,
                        syntax='asa',
                        CiscoConfParse=self)

                elif syntax=='junos':
                    # string - assume a filename... open file, split and parse
                    if self.debug:
                        _log.debug("parsing from '{0}' with junos syntax".format(config))
                    f = open(config, mode="rU")
                    text = f.read()
                    rgx = re.compile(linesplit_rgx)

                    config = self.convert_braces_to_ios(rgx.split(text))
                    ## FIXME I am shamelessly abusing the IOSConfigList for now...
                    self.ConfigObjs = ccp.IOSConfigList(config,
                        comment_delimiter=comment, 
                        debug=debug,
                        factory=factory,
                        ignore_blank_lines=ignore_blank_lines,
                        syntax='junos',
                        CiscoConfParse=self)
                else:
                    raise ValueError("FATAL: '{}' is an unknown syntax".format(syntax))

            except IOError:
                print("[FATAL] CiscoConfParse could not open '%s'" % config)
                raise RuntimeError
        else:
            raise RuntimeError("[FATAL] CiscoConfParse() received" + 
                " an invalid argument\n")
        self.ConfigObjs.CiscoConfParse = self
