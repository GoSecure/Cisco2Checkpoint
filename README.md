# cisco2checkpoint Migration Tool

Cisco to Checkpoint is a conversion tool developed by GoSecure to help during migration projects. The tool has the ability to convert objects such as networks, services, groups and even firewall rules.

The tool requires python 2.7 and a forked version of [ciscoconfparse](https://pypi.python.org/pypi/ciscoconfparse) (included).

Supported input syntax is currently IOS and ASA. The script output a file in dbedit syntax.

The script was run on nearly 10 different configurations and leads to many success stories but the tool is still experimental. Use it at your own risk.


## Install

```
git clone --recursive https://github.com/gosecure/cisco2checkpoint c2c
cd c2c
```

## Simple use case: Fresh Install

The easiest and most basic way to convert a cisco configuration file, exported with `show run`, as follows.

```
python2.7 c2c.py --export \
    --ciscoFile 'some_cisco_conf.txt' \
    --syntax asa \
    --policy My_Policy \
    --installOn My_Firewall \
    --output 'network_script.txt' \
```

As a result, the file `network_script.txt` is created and contains the converted policy. Upload the file on the SmartCenter server. Note that you will need a user with a bash shell to upload using SSH. To do so, run `chsh -s /bin/bash` and then logout to apply the change.

Before import, make sure that no "write mode" session is open with SmartDashboard. Also make sure that there is **no empty lines** and that the return characters are **\n** (not \r\n). Don't forget to **take a backup or a DRC (Database Revision Control)**.

To perform the import, run:

```
dbedit -local -f network_script.txt -ignore_script_failure -continue_updating
```

## Advanced use case: Adding FW to existing policy

If a Checkpoint policy already exists on the SmartCenter server, the script must be aware of the existing objects. It is possible to export those objects in xml format and specify them using a new argument.

First run the following on the SmartCenter.

```
echo "printxml network_objects" > printxml_netobj.txt
echo "printxml services" > printxml_services.txt
echo '<a>' > customer_network_objects.xml
dbedit -local -f printxml_netobj.txt >> customer_network_objects.xml
echo '</a>' >> customer_network_objects.xml
echo '<a>' > customer_service_objects.xml
dbedit -local -f printxml_services.txt >> customer_service_objects.xml
echo '</a>' >> customer_service_objects.xml
```

Then copy both xml files in the root of the repository and run as follows.

```
python2.7 c2c.py --export \
    --ciscoFile 'some_cisco_conf.txt' \
    --cpPortsFile 'customer_service_objects.xml' \
    --cpNetObjFile 'customer_network_objects.xml' \
    --syntax asa \
    --policy My_Policy \
    --installOn My_Firewall \
    --output 'network_script.txt' 
```

As a result, the file `network_script.txt` is created and contains the converted policy. Upload the file on the SmartCenter server. Note that you will need a user with a bash shell to upload using SSH. To do so, run `chsh -s /bin/bash` and then logout to apply the change.

Before import, make sure that no "write mode" session is open with SmartDashboard. Also make sure that there is **no empty lines** and that the return characters are **\n** (not \r\n). Don't forget to **take a backup or a DRC (Database Revision Control)**.

To perform the import, run:

```
dbedit -local -f network_script.txt -ignore_script_failure -continue_updating
```

## Verify the conversion

Simply replace the `--export` argument by `--verify` and add `--format text` to generate the configuration into a human-readable format. For example:

```
python2.7 c2c.py --verify \
    --format text \
    --ciscoFile 'some_cisco_conf.txt' \
    --syntax asa \
    --policy My_Policy \
    --installOn My_Firewall \
    --output 'network_script_verify.txt' \
```

In the example below, the last three lines show three `access-list` that were used to generate a single checkpoint rule:

```
ACLRule(name=acl_inside,src=N-Prod-Wks-10.12.160.0_19;N-LAN-Wks-10.16.160.0_24;N-Prod-Wks-10.21.60.0_22,dst=G-xmpp-Internet,port=any,action=permit,pol=FW-Temp,inst=,disabled=False,desc=Access to X)
 Desc:Access to X
 Src: CiscoNet(name=N-Prod-Wks-10.12.160.0_19,ipAddr=10.12.160.0/255.255.224.0,desc=,alias=)
 Src: CiscoNet(name=N-LAN-Wks-10.16.160.0_24,ipAddr=10.16.160.0/255.255.255.0,desc=,alias=)
 Src: CiscoNet(name=N-Prod-Wks-10.21.60.0_22,ipAddr=10.21.60.0/255.255.252.0,desc=,alias=N-Prod-Wkstn-10.21.60.0_22)
 Dst: CiscoNetGroup(name=G-xmpp-Internet,desc= description Routes de xmpp via Internet,nbMembers=6,alias=)
   CiscoNet(name=N-xmpp-Int-160.43.250.0_24,ipAddr=160.43.250.0/255.255.255.0,desc=,alias=)
   CiscoNet(name=N-xmpp-Int-206.156.53.0_24,ipAddr=206.156.53.0/255.255.255.0,desc=,alias=)
 Port: CiscoAnyPort(name=any,port=0,desc=,alias=)
 Verify: <ASAAclLine # 2531 'access-list acl_inside extended permit ip object N-Prod-Wks-10.12.160.0_19 object-group G-xmpp-Internet log'>
 Verify: <ASAAclLine # 2532 'access-list acl_inside extended permit ip object N-LAN-Wks-10.16.160.0_24 object-group G-xmpp-Internet log'>
 Verify: <ASAAclLine # 2534 'access-list acl_inside extended permit ip object N-Prod-Wkstn-10.21.60.0_22 object-group G-xmpp-Internet log'>
```


## Implicit Behaviors

**Firewall rationalization**

By default, firewall rules are merged together if it doesn't affect the security of the policy. For two rules to be merged, all fields except one must be identical. Fewer firewall rules result in better performance and ease of management, which often increase security.

**Objects Reuse**

When two objects with the same properties are found, they are merged. For example, if two hosts are defined with the same IP address, the first name is taken.

**Dynamic Object Generation**

When a host is defined in a group or an access-list without a name, it is automatically created. The reason is that in Checkpoint everything needs to be a defined object.


## Modifiers

Those modifiers can be used for specific needs, such as specifying color on objects and enable logging on every rule.


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


## Customization

A config file is located in `./config.py`. Most users shouldn't need to modify it. However, it is worth knowing the existence of this file. Users will find object prefixes for dynamically created objects, excluded checkpoint services, illegal expression replacements and association tables for ports and protocols.


## Warning

**Layer 2 vs Layer 3 :** As some of you may know, Checkpoint policy is layer-3 based, meaning that firewall interfaces are completely abstracted from the policy. In fact, it is not possible to assign a rule to an interface like on Cisco. For this reason, you will find many *Drop All* rules within the policy and other rules that make no sense in the context of a layer-3 stateful firewall. Thus, a review must **always** be performed after the import.

**Cisco syntax :** Cisco tends to be very flexible when it's time to write a line. Some keywords are optional and it is not required to define everything as an object. It also allows one to define an object in multiple ways. Unfortunately, this lead to little hacks in the code.


## License

cisco2checkpoint is licensed GPLv3; Copyright [GoSecure](https://gosecure.net), 2015-2017.


## Author and Thanks

cisco2checkpoint was developed by Martin Dubé (mdube at gosecure.ca)

Special thanks:
 - David Michael Pennington for his awesome work on [ciscoconfparse](https://github.com/mpenning/ciscoconfparse)
 - Olivier Bilodeau for helping me rebase the project and follow good practices
