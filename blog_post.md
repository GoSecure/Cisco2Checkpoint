# cisco2checkpoint - a Cisco to Checkpoint conversion tool

## Introduction

GoSecure has conducted several security migration projects in the past years, gathering technical experience on top NGFW products of the markets. These projects not only required deep knowledge of two separate products (the source and the destination), but also the ability to build tools and automate tasks. Unfortunatly, tools released by vendors are either limited, not enough flexible or simply hard to find.

Today, GoSecure wish to contribute to the Open Source community by releasing under the GPLv3 license a useful tool used during cisco to checkpoint firewall migration, the cisco2checkpoint converter.


## Install

cisco2checkpoint can be found on github.

```
git clone --recursive https://github.com/GoSecure/Cisco2Checkpoint c2c
```

Instructions can be found on the [github page](https://github.com/GoSecure/Cisco2Checkpoint).


## How it works?

The tool import a cisco ASA or IOS running config file and convert it in a file parsable by [dbedit](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk30383), a tool provided by Checkpoint to automate tasks.  The converter supports objects including:

| Checkpoint objects           | Cisco syntax                    |
|:-----------------------------|:--------------------------------|
| hosts/networks/ranges        | "object network"                |
| services                     | "object service"                |
| hosts/networks/ranges groups | "object-group network"          |
| service groups               | "object-group service"          |
| firewall rules               | "ip access-list", "access-list" |


For instance, be the host definition below from a ASA config file.

```
object network myHost
 description someone's VM in lab
 host 10.0.1.201
```

The following text block will be produced by the script. Color can be customized with an additional argument.

```
create host_plain myHost
modify network_objects myHost ipaddr 10.0.1.201
modify network_objects myHost comments "someone's VM in lab"
modify network_objects myHost color "black"
update network_objects myHost
```

A security analyst then use dbedit to import the data.


## Real life example

The true power of this tool is on huge policies. The extract below is a summary of one of the biggest policy that was converted by the tool.

```
...
# Number of hosts (imported from cisco file): 149
# Number of hosts (imported from checkpoint xml): 0
# Number of hosts (dynamically created): 168
# Number of hosts (after merge/cleanup): 0
# Number of subnet (imported from cisco file): 63
# Number of subnet (imported from checkpoint xml): 0
# Number of subnet (dynamically created): 36
# Number of subnet (after merge/cleanup): 0
...
# Number of acl rules (not imported: established): 52
# Number of acl rules (not imported: source port): 276
# Number of acl rules (before merge/cleanup): 2012
# Number of acl rules (after merge/cleanup): 746
# Number of single ports (imported from cisco file): 307
# Number of single ports (imported from checkpoint xml): 0
# Number of single ports (dynamically created): 27
# Number of port range (imported from cisco file): 0
# Number of port range (imported from checkpoint xml): 0
# Number of port range (dynamically created): 21
```


### Dynamic Object Creation

An important difference between cisco and checkpoint is that checkpoint require anything to be an object. For example, an IP address must be defined through a host object to be used in a group while cisco doesn't need an explicit definition.

During this project, 149 hosts were defined in the cisco file but 168 new hosts needed to be created *on the fly* because they were referenced by a group or an access-list.


### Prevent inconsistencies

The script identified 52 access-list with the statement "established" and 276 access-list with the use of source port, which shows an old way to configure a firewall. It is rare to need a source port in the rule of a NGFW. For this reason, the script excluded these rules from the import and a security analyst took care of them.

This finding have lead to an improvement of the customer's policy. In fact, those rules were giving unwanted access in the environment.


### Firewall rationalization

Finally, one of the most time-saving feature of the tool is the firewall rules rationalization. In the current example, the tool merged 2012 access-list into 746 firewall rules, keeping almost only 30% of the initial access-list while keeping the same level of security.

The number of rules in a firwall policy have an important effect on the management. A clean policy reduce the time needed to make a change. It also make the understanding of the policy much easier, reducing risks of errors during a change.


## Conclusion

This contribution aim to help firewall administrators by saving time and performing security improvements early when migrating to a new Checkpoint firewall.
