# Firewall Project
### XDP Firewall Consumer

-----

This module work as a Consumer


#### Description

The consumer will listen to this channel, which is a python program that gets the message from the message publisher and decided whether to block the IPs or unblock them
based on the state attached to the message. If the state is True, it means the IP list, must be attached to a defined xdp device (NIC) on the server and this function will
block them and also dump the list in a light weighted local database called "iplist.db". If the state is False, it means the IP list, must be removed from defined xdp device(NIC) on the server and this function will unblock them and also remove the IPs from "iplist.db" file. In case, If the consumer app, stops working on the CDN node, the 
filter will be removed from device NIC but at the start, it will load the db file again and the filter will assign again. 

#### Install
On consumer side (Here by consumer, we meant CDN nodes)

```
sudo apt-get install python-pip
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
sudo pip install -r requirements.txt
```


####  Usage

Blocking/Unblocking IP addresses at driver level of CDN Nodes.
