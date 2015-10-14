C2C_VERSION = '0.16 - 2015-06-17'
C2C_DEBUG = False

MAX_FWRU_NAME_LEN = 30	# Product limitation
DEFAULT_FORMAT = 'dbedit'
DEFAULT_CP_PORT_FILE = 'cp\\services_objects.xml'
DEFAULT_CP_NETOBJ_FILE = 'cp\\network_objects.xml'
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
SUPPORTED_PROTO = ['tcp', 'udp', 'ip', 'icmp', 'esp', 'ah']			# rpc is not supported.
SUPPORTED_LAYER3_PROTO = ['ip', 'icmp']
SUPPORTED_OBJ_FLAGS = ['object-group', 'object', 'host', 'any4', 'any']
SUPPORTED_PORT_FLAGS = ['eq', 'range', 'object-group']
SUPPORTED_FLAGS = ['object-group', 'object', 'eq', 'log', 'host', 'any4', 'any']
SUPPORTED_ANY_FLAGS = ['any', 'any4']
FW_RULE_INDEX = -1

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
				 # 'All-' : 'All_', \		# Removed for BDC PROD
				 # '-All' : '_All', \		# Removed for BDC PROD
				  'All-Perimeter' : 'All_Perimeter', \
				  'In-Domain' : 'In_Domain', \
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
		
CONFIG_FILE_SUFFIX = '.CONFG'