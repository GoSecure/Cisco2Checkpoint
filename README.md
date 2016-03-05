# cisco2checkpoint migration tool

Cisco to Checkpoint migration tool used during migration projects. This tool was 
tested and built to run on Linux.

Dependencies

* ciscoconfparse (Is currently forked)
* Python 3.4


## Features

* Support Cisco IOS and ASA
* Support Checkpoint R77.30
* Support the following protocols: ICMP, OSPF, ESP, AH, AHP, VRRP, SKIP, GRE
* Support TCP/IP and TCP/UDP
* Support already existing objects using dbedit xml exports
* Support IOS and ASA access-list convertion
* Support firewall rules rationalization (merge redundancies)

### Help
```
usage: c2c.py [-h] [-v] [--debug] [--summary] [--export] [--verify]
              [--search TEXT] [--ciscoFile FILE] [--ciscoDir DIR]
              [--cpPortsFile FILE] [--cpNetObjFile FILE] [--syntax SYNTAX]
              [--format FORMAT] [--output FILE] [--filter CLASS] [--stdout]
              [--policy POLICY] [--installOn FWs] [--natInstallOn FW]
              [--color COLOR] [--force-log] [--startIndex INDEX]
              [--disableRules] [--flattenInlineNetGroups]
              [--flattenInlineSvcGroups]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --debug               Run the tool in debug mode

Action:
  Select one of these action

  --summary, -u         Print a summary of what is parsed and what would be
                        migrated.
  --export, -e          Export configuration. Use --format to determine
                        format.
  --verify              Export configuration like --export but in text format
                        and in a verifyable format.
  --search TEXT, -s TEXT
                        Search for a specific object.

Import config:
  --ciscoFile FILE, -c FILE
                        Cisco config file to parse.
  --ciscoDir DIR, -d DIR
                        config directory to parse. Will read only *.Config
                        files
  --cpPortsFile FILE    Checkpoint xml port file to parse. Default:
                        cp/services_objects.xml
  --cpNetObjFile FILE   Checkpoint xml network objects file to parse. Default:
                        cp/network_objects.xml
  --syntax SYNTAX       Specify the cisco syntax. Valid values: ios, asa.
                        Default: ios

Options:
  --format FORMAT, -f FORMAT
                        Specify the format. Valid values: dbedit, text.
                        Default: dbedit
  --output FILE, -o FILE
                        Output file. Default: network_script.txt
  --filter CLASS        Filter a class name, e.g. CiscoHost, CiscoPort,
                        CiscoFwRule. Can use option several times.
  --stdout              Print output to stdout.

Export Modifiers:
  --policy POLICY       The policy name. Relevant with --export only. Default:
                        Standard
  --installOn FWs       Specify the checkpoint object to install rules on.
  --natInstallOn FW     The firewall to use for all hide and static NAT rules.
  --color COLOR         The color to use for new objects.
  --force-log           Force track=Log on all firewall rules
  --startIndex INDEX    Index to start importing firewall rules. Default: 0
  --disableRules        Disable all firewall rules.
  --flattenInlineNetGroups
                        Flatten groups with prefix DM_INLINE_NETWORK_ so
                        members are added to firewall rules instead of the
                        group.
  --flattenInlineSvcGroups
                        Flatten groups with prefix DM_INLINE_SERVICE_ so
                        members are added to firewall rules instead of the
                        group.

```

## Basic usage

Print a summary of what is parsed

    ./cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --summary

Search some objects

    ./cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --search 'obj-172.16.66.0' --format text
    ./cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --search 'obj-172.16.66.0' --format text --filter CiscoHost

Export in a human readable form
    ./cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --export --format text
  
Export for dbedit
    ./cisco2checkpoint.py --ciscoFile 'cisco-run-conf.txt' --export --format dbedit --policy Standard --installOn fw01 --installOn fw02

Import to checkpoint
    dbedit -local -f network_script.txt


## Advanced usage
```
# Prerequisite: generate a custom list of network and services objects
# so let the script know about already existing objects.
#
# Run the following on a SmartCenter server.
echo "printxml network_objects" > printxml_netobj.txt
echo "printxml services" > printxml_services.txt
echo '<a>' > customer_network_objects.xml
dbedit -local -f printxml_netobj.txt >> customer_network_objects.xml
echo '</a>' >> customer_network_objects.xml
echo '<a>' > customer_service_objects.xml
dbedit -local -f printxml_services.txt >> customer_service_objects.xml
echo '</a>' >> customer_service_objects.xml

python2.7 c2c.py --cpPortsFile 'cp/customer_service_objects.xml'
    --cpNetObjFile 'cp/customer_network_objects.xml'
    --ciscoFile '_archive/cisco_customer/some_cisco_conf.txt'
    --syntax asa
    --verify
    --policy New_Policy --installOn MyFirewall
    --color 'blue'
    --startIndex 0
    --format text
    --output 'network_script_verify.txt'
    --flattenInlineNetGroups
    --flattenInlineSvcGroups
    --debug
    > 'network_script_debug.txt'
```

## Known limitations

 * The script convert "permit" to "allow" and "deny" to "deny". The script 
   does generate rules with "reject" or checkpoint proprietary actions.
 * The script support only None and Log tracking.
 * The script does not feed the "VPN" field.
 * The NAT rule translation is buggy.
 * The script does not support IPv6 (so any4 or any6 become any)
 * Redundant groups are not merged yet

## License

TBD
