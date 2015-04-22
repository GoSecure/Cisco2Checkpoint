C2C_VERSION = '0.09 - 2015-04-20'
C2C_DEBUG = False

DEFAULT_FORMAT = 'dbedit'
DEFAULT_CP_PORT_FILE = 'cpports\\checkpoint_ports.xml'
DEFAULT_OUTPUT_FILE = 'network_script.txt'
DEFAULT_POLICY = 'Standard'
DEFAULT_INSTALLON = 'atcl'

WARN_PREFIX = '#[-] '
MSG_PREFIX = '#[+] '
NEW_NET_PREFIX = 'N_'
NEW_HOST_PREFIX = 'H_'
NEW_RANGE_PREFIX = 'R_'
TCPUDP_PREFIX = 'TU_'
TCP_PREFIX = 'TCP_'
UDP_PREFIX = 'UDP_'

ANY_ICMP = 'icmp-proto'
ANY_ESP = 'ESP'
ANY_AH = 'AH'
SUPPORTED_PROTO = ['tcp', 'udp', 'ip', 'icmp', 'esp', 'ah']			# rpc is not supported.
SUPPORTED_LAYER3_PROTO = ['ip', 'icmp']
SUPPORTED_OBJ_FLAGS = ['object-group', 'object', 'host', 'any4', 'any']
SUPPORTED_PORT_FLAGS = ['eq', 'range', 'object-group']
SUPPORTED_FLAGS = ['object-group', 'object', 'eq', 'log', 'host', 'any4', 'any']
SUPPORTED_ANY_FLAGS = ['any', 'any4']
FW_RULE_INDEX = 0

HOST_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost']
NETOBJ_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost','CiscoNet','CiscoRange']
SVCOBJ_CLASSES = ['CiscoSinglePort','CiscoPortRange','CiscoPortGroup','CiscoAnyPort','CiscoIcmp','CiscoAnyIcmp','CiscoEspProto','CiscoAHProto']
ANY_CLASSES = ['CiscoAnyHost', 'CiscoAnyIcmp', 'CiscoAnyPort']

# Classes that have a name (searchable by name)
NETOBJ_NAMED_CLASSES = ['CiscoName','CiscoHost','CiscoAnyHost','CiscoNet','CiscoRange','CiscoNetGroup']
SVCOBJ_NAMED_CLASSES = ['CiscoSinglePort','CiscoPortRange','CiscoPortGroup','CiscoAnyPort','CiscoIcmp','CiscoAnyIcmp','CiscoEspProto','CiscoAHProto']


EXCLUDE_PORTS = ['ssl_v3', 'ssh_version_2', 'ftp-bidir', 'ftp-pasv', 'ftp-port', \
				'sip_tls_not_inspected', 'H323_any', 'H323_ras_only', 'snmp-read', \
				'dhcp-relay', 'dhcp-req-localmodule', 'MSSQL_resolver']

# Translate cisco value => checkpoint value				
ICMP_DIC = { 'unreachable' : 'dest-unreach', \
			 'echo' : 'echo-request' }
			 
ILLEGAL_DIC = { '' : '', \
				  'All-' : 'All', \
				  '-All' : 'All', \
				  'In-Domain' : 'InDomain', \
			  }	
			  
PORT_DIC = { 'ftp-data' : '20', \
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
		'www' : '80', \
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
		'sqlnet' : '1521', \
		'h323' : '1720', \
		'pptp' : '1723', \
		'sip' : '5060 5061', \
		'aol' : '5190', \
		'pcanywhere-data' : '5631', \
		'pcanywhere-status' : '5632', \
		}	
		
CONFIG_FILE_SUFFIX = '.Config'