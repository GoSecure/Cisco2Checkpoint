# Introducing Cisco2Checkpoint - a Cisco to Checkpoint Conversion Tool

## Introduction

GoSecure has conducted several network security migration projects in the past years, gathering technical experience on top Next-Generation Firewall (NGFW) products. These projects not only required deep knowledge of two separate products (the source and the destination), but also the ability to build tools and automate tasks. Unfortunately, tools released by vendors are either limited, not flexible enough or simply hard to find.

Today, GoSecure wish to contribute to the Open Source community by releasing under the GPLv3 license a useful tool used during cisco to checkpoint firewall migration, the cisco2checkpoint converter.


## Install

cisco2checkpoint can be found on GitHub.

```
git clone --recursive https://github.com/GoSecure/Cisco2Checkpoint c2c
```

Instructions can be found on the [GitHub page](https://github.com/GoSecure/Cisco2Checkpoint).


## How it works?

The tool imports a Cisco ASA or IOS running config file and converts it in a file that can be parsed by [dbedit](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk30383), a tool provided by Checkpoint to automate tasks.  The converter supports objects including:

| Checkpoint objects           | Cisco syntax                    |
|:-----------------------------|:--------------------------------|
| hosts/networks/ranges        | "object network"                |
| services                     | "object service"                |
| hosts/networks/ranges groups | "object-group network"          |
| service groups               | "object-group service"          |
| firewall rules               | "ip access-list", "access-list" |


For instance, be the host definition below from an ASA config file:

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

A security analyst then uses `dbedit` to import the data.


## Real-life example

The true power of this tool comes to life on huge policies. The extract below is a summary of one of the biggest policy that was converted by the tool.

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

An important difference between Cisco and Checkpoint is that Checkpoint requires anything to be an object. For example, an IP address must be defined through a host object to be used in a group while Cisco doesn't need an explicit definition.

During this project, 149 hosts were defined in the Cisco file but 168 new hosts needed to be created *on the fly* because they were referenced by a group or an access-list.


### Prevent Inconsistencies

The script identified 52 access-list with the statement "established" and 276 access-list with the use of source port, which shows an old way to configure a firewall. It is rare to need a source port in the rule of a NGFW. For this reason, the script excluded these rules from the import and a security analyst took care of them.

This cleanup leads to an improvement of the customer's policy. In fact, those rules were potentially allowing unwanted access in the environment.


### Firewall Rationalization

Finally, the most time-saving feature of the tool is the firewall rules rationalization. In the current example, the tool merged 2012 access-list into 746 firewall rules, keeping almost only 30% of the initial access-list while keeping the same level of security.

The number of rules in a firewall policy [has an important effect on its management](https://www.eng.tau.ac.il/~yash/05440153.pdf). A clean policy reduces the time required to make a change. It also makes the policy much easier to understand, reducing risks of errors during a change.


## Conclusion

This piece of code aims to help firewall administrators by saving time and performing security improvements early when migrating to a new Checkpoint firewall. Hopefully it will be  useful to some of you.
