C2C_VERSION = '0.16 - 2015-06-17'
C2C_DEBUG = False

MAX_ACLRU_NAME_LEN = 30    # Product limitation
DEFAULT_FORMAT = 'dbedit'
DEFAULT_CP_PORT_FILE = 'cp/services_objects.xml'
DEFAULT_CP_NETOBJ_FILE = 'cp/network_objects.xml'
DEFAULT_OUTPUT_FILE = 'network_script.txt'
DEFAULT_POLICY = 'Standard'
DEFAULT_INSTALLON = 'vs01'
DEFAULT_NAT_INSTALLON = 'vs01'

WARN_PREFIX = '#[-] '
MSG_PREFIX = '#[+] '
NEW_NET_PREFIX = 'N_'
NEW_HOST_PREFIX = 'H_'
NEW_RANGE_PREFIX = 'R_'
NEW_GROUP_PREFIX = 'G_'
TCPUDP_PREFIX = 'TU_'
TCP_PREFIX = 'TCP_'
UDP_PREFIX = 'UDP_'

DM_INLINE_NET_PREFIX = 'DM_INLINE_NETWORK'
DM_INLINE_SVC_PREFIX = 'DM_INLINE_SERVICE'
DM_INLINE_TCP_PREFIX = 'DM_INLINE_TCP'
DM_INLINE_UDP_PREFIX = 'DM_INLINE_UDP'

ANY_ICMP = 'icmp-proto'
ANY_ESP = 'ESP'
ANY_AH = 'AH'
ANY_OSPF = 'ospf'
ANY_VRRP = 'vrrp'
ANY_SKIP = 'SKIP'
ANY_GRE = 'gre'

# rpc is not supported.
SUPPORTED_PROTO = ['tcp', 'udp', 'ip', 'icmp', 'esp', 'ah', 'ospf', 'esp', \
                  'ahp', 'vrrp', 'skip', 'gre'] 
#SUPPORTED_LAYER3_PROTO = ['ip', 'icmp']
#SUPPORTED_OBJ_FLAGS = ['object-group', 'object', 'host', 'any4', 'any']
#SUPPORTED_PORT_FLAGS = ['eq', 'range', 'object-group']
#SUPPORTED_FLAGS = ['object-group', 'object', 'eq', 'log', 'host', 'any4', 'any']
#SUPPORTED_ANY_FLAGS = ['any', 'any4']
ACL_RULE_INDEX = -1

HOST_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost']
NETOBJ_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost','CiscoNet','CiscoRange']
SVCOBJ_CLASSES = ['CiscoSinglePort','CiscoPortRange','CiscoPortGroup','CiscoAnyPort','CiscoIcmp','CiscoAnyIcmp','CiscoEspProto','CiscoAHProto']
ANY_CLASSES = ['CiscoAnyHost', 'CiscoAnyIcmp', 'CiscoAnyPort']
GROUP_CLASSES = ['CiscoNetGroup', 'CiscoPortGroup']

# Classes that have a name (searchable by name)
NETOBJ_NAMED_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost','CiscoNet','CiscoRange','CiscoNetGroup']
SVCOBJ_NAMED_CLASSES = ['CiscoSinglePort','CiscoPortRange','CiscoPortGroup','CiscoAnyPort','CiscoIcmp','CiscoAnyIcmp','CiscoEspProto','CiscoAHProto']


EXCLUDE_PORTS = ['ssl_v3', 'ssh_version_2', 'ftp-bidir', 'ftp-pasv', 'ftp-port', \
                'sip_tls_not_inspected', 'H323_any', 'H323_ras_only', 'snmp-read', \
                'dhcp-relay', 'dhcp-req-localmodule', 'MSSQL_resolver']

# Translate cisco value => checkpoint value                
ICMP_DIC = { 'unreachable' : 'dest-unreach', \
             'echo' : 'echo-request', \
             'information-request' : 'info-req', \
             'information-reply' : 'info-reply', \
             'mask-reply' : 'mask-reply', \
             'mask-reply' : 'mask-reply', \
             'parameter-problem' : 'param-prblm', \
             'mobile-redirect' : 'redirect'}
             
ILLEGAL_DIC = { '' : '', \
                # 'All-' : 'All_', \        # Removed for a customer
                # '-All' : '_All', \        # Removed for a customer
                'All-Perimeter' : 'All_Perimeter', \
                'In-Domain' : 'In_Domain', \
                'GigabitEthernet' : 'Gi', \
                '(' : '-', \
                ')' : '', \
              }    
              
PORT_DIC = { 'echo' : '7', \
        'daytime' : '13', \
        'ftp-data' : '20', \
        'ftp' : '21', \
        'ssh' : '22', \
        'telnet' : '23', \
        'smtp' : '25', \
        'whois' : '43', \
        'tacacs' : '49', \
        'domain' : '53', \
        'domain-tcp' : '53', \
        'domain-udp' : '53', \
        'bootps' : '67', \
        'bootpc' : '68', \
        'tftp' : '69', \
        'www' : '80', \
        'pop2' : '109', \
        'pop3' : '110', \
        'sunrpc' : '111', \
        'ntp' : '123', \
        'netbios-ns' : '137', \
        'netbios-dgm' : '138', \
        'netbios-ssn' : '139', \
        'imap4' : '143', \
        'snmp' : '161', \
        'snmptrap' : '162', \
        'ldap': '389', \
        'ldaps' : '636', \
        'https' : '443', \
        'isakmp' : '500', \
        'syslog' : '514', \
        'lpd' : '515', \
        'rtsp' : '554', \
        'citrix-ica' : '1494', \
        'sqlnet' : '1521', \
        'h323' : '1720', \
        'pptp' : '1723', \
        'sip' : '5060 5061', \
        'aol' : '5190', \
        'pcanywhere-data' : '5631', \
        'pcanywhere-status' : '5632' \
        }    

PROTO_DIC= { \
           '0':'HOPOPT',\
           '1':'ICMP',\
           '2':'IGMP',\
           '3':'GGP',\
           '4':'IPv4',\
           '5':'ST',\
           '6':'TCP',\
           '7':'CBT',\
           '8':'EGP',\
           '9':'IGP',\
           '10':'BBN-RCC-MON',\
           '11':'NVP-II',\
           '12':'PUP',\
           '13':'ARGUS',\
           '14':'EMCON',\
           '15':'XNET',\
           '16':'CHAOS',\
           '17':'UDP',\
           '18':'MUX',\
           '19':'DCN-MEAS',\
           '20':'HMP',\
           '21':'PRM',\
           '22':'XNS-IDP',\
           '23':'TRUNK-1',\
           '24':'TRUNK-2',\
           '25':'LEAF-1',\
           '26':'LEAF-2',\
           '27':'RDP',\
           '28':'IRTP',\
           '29':'ISO-TP4',\
           '30':'NETBLT',\
           '31':'MFE-NSP',\
           '32':'MERIT-INP',\
           '33':'DCCP',\
           '34':'3PC',\
           '35':'IDPR',\
           '36':'XTP',\
           '37':'DDP',\
           '38':'IDPR-CMTP',\
           '39':'TP++',\
           '40':'IL',\
           '41':'IPv6',\
           '42':'SDRP',\
           '43':'IPv6-Route',\
           '44':'IPv6-Frag',\
           '45':'IDRP',\
           '46':'RSVP',\
           '47':'GRE',\
           '48':'DSR',\
           '49':'BNA',\
            '50':'ESP',\
            '51':'AH',\
            '52':'I-NLSP',\
            '53':'SWIPE',\
            '54':'NARP',\
            '55':'MOBILE',\
            '56':'TLSP',\
            '57':'SKIP',\
            '58':'IPv6-ICMP',\
            '59':'IPv6-NoNxt',\
            '60':'IPv6-Opts',\
            '62':'CFTP',\
            '64':'SAT-EXPAK',\
            '65':'KRYPTOLAN',\
            '66':'RVD',\
            '67':'IPPC',\
            '69':'SAT-MON',\
            '70':'VISA',\
            '71':'IPCV',\
            '72':'CPNX',\
            '73':'CPHB',\
            '74':'WSN',\
            '75':'PVP',\
            '76':'BR-SAT-MON',\
            '77':'SUN-ND',\
            '78':'WB-MON',\
            '79':'WB-EXPAK',\
            '80':'ISO-IP',\
            '81':'VMTP',\
            '82':'SECURE-VMTP',\
            '83':'VINES',\
            '84':'TTP',\
            '84':'IPTM',\
            '85':'NSFNET-IGP',\
            '86':'DGP',\
            '87':'TCF',\
            '88':'EIGRP',\
            '89':'OSPFIGP',\
            '90':'Sprite-RPC',\
            '91':'LARP',\
            '92':'MTP',\
            '93':'AX.25',\
            '94':'IPIP',\
            '95':'MICP',\
            '96':'SCC-SP',\
            '97':'ETHERIP',\
            '98':'ENCAP',\
            '100':'GMTP',\
            '101':'IFMP',\
            '102':'PNNI',\
            '103':'PIM',\
            '104':'ARIS',\
            '105':'SCPS',\
            '106':'QNX',\
            '107':'A/N',\
            '108':'IPComp',\
            '109':'SNP',\
            '110':'Compaq-Peer',\
            '111':'IPX-in-IP',\
            '112':'VRRP',\
            '113':'PGM',\
            '115':'L2TP',\
            '116':'DDX',\
            '117':'IATP',\
            '118':'STP',\
            '119':'SRP',\
            '120':'UTI',\
            '121':'SMP',\
            '122':'SM',\
            '123':'PTP',\
            '124':'ISIS over IPv4',\
            '125':'FIRE',\
            '126':'CRTP',\
            '127':'CRUDP',\
            '128':'SSCOPMCE',\
            '129':'IPLT',\
            '130':'SPS',\
            '131':'PIPE',\
            '132':'SCTP',\
            '133':'FC',\
            '134':'RSVP-E2E-IGNORE',\
            '135':'Mobility Header',\
            '136':'UDPLite',\
            '137':'MPLS-in-IP',\
            '138':'manet',\
            '139':'HIP',\
            '140':'Shim6',\
            '141':'WESP',\
            '142':'ROHC',\
            '255':'Reserved'\
}
        
CONFIG_FILE_SUFFIX = '.CONFG'
