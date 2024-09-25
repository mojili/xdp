#!/usr/bin/python3
"""
This is the Message broker Consumer and XDP Firewall version 1
It gets list of IPs from defined "black-listed" channel and based on state value, decides to add or delete that IP.
"""
#Append local package path
#import sys, os
#PACKAGE_PARENT = '..'
#SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
#sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

# Here is the required modules
import pika, json, yaml
import netaddr, pickledb, time
from bcc import BPF
import logging

# Read configs through yaml file
with open('config.yml', mode='r') as file:
    cfg = yaml.full_load(file)

# Log file definitions
logging.basicConfig(filename='xdp.log', level=logging.INFO)


db = pickledb.load('iplist.db', False)
device = cfg['devices']

c_text = """
#define KBUILD_MODNAME "Dk CDN Droper"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

 BPF_TABLE("hash", uint32_t, int, blacklist, 100000);

 static inline int parse_ipv4(void *data, u64 offset, void *data_end) {
    struct iphdr *iph = data + offset;
    if ((void*)&iph[1] > data_end)
        return 1;
    uint32_t saddr = ntohl(iph->saddr);
    if (blacklist.lookup(&saddr))
        return 1;
    return 0 ;
 }


 static inline int parse_ipv6(void *data, u64 offset, void *data_end) {
    struct ipv6hdr *ip6h = data + offset;
    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
 }


 int cdnfw(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    long *value;
    uint16_t h_proto;
    uint64_t offset = 0;
    uint32_t result = 0;
    offset = sizeof(*eth);
    if (data + offset  > data_end)
        return XDP_PASS;
    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP))
        result = parse_ipv4(data, offset, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
        result = parse_ipv6(data, offset, data_end);

    if (result)
        return XDP_DROP;
    return XDP_PASS;
 }
 """
b = BPF(text=c_text, cflags=["-w", "-DRETURNCODE=XDP_DROP", "-DCTXTYPE=xdp_md"])
fn = b.load_func("cdnfw", BPF.XDP)
for nic in device:
    b.attach_xdp(nic, fn, 0)
bl = b["blacklist"]

def add_ip(ip_add_list):
    """This function, get the IP address and dump it to db for adding to black list
    Input: IP address which received from message broker with "true" statue
    Output: dumped IPs to iplist.db
    """
    for ip in ip_add_list:
        ipaddr = netaddr.IPAddress(ip)
        db.set(str(ipaddr), "1")
        bl[bl.Key(ipaddr)] = bl.Leaf(1)
    db.dump()
    logging.info("new list of IPs added to blacklist")
    return True

def delete_ip(ip_del_list):
    """This function, get the IP address and dump it to db for removing from black list
    Input: IP address which received from message broker with "false" status
    Output: dumped IPs to iplist.db
    """
    for ip in ip_del_list:
        ipaddr = netaddr.IPAddress(ip)
        del bl[bl.Key(ipaddr)]
        db.rem(str(ipaddr))
    db.dump()
    logging.info("IPs removed from blacklist")
    return True

credentials = pika.PlainCredentials(cfg['auth']['rabbit_user'],cfg['auth']['rabbit_pass'])
parameters = pika.ConnectionParameters(credentials=credentials)
rabbit_server = cfg['rabbit_hosts']['host']
connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbit_server, credentials=credentials))
channel = connection.channel()
channel.exchange_declare(exchange='black-listed', exchange_type='fanout')
result = channel.queue_declare(queue='', exclusive=True)
queue_name = result.method.queue
channel.queue_bind(exchange='black-listed', queue=queue_name)

def callback(ch, method, properties, body):
    """This function, Get the message from message broker and based on the state, pass the ip addresses
    to one of the "add_ip" or "delete_ip" functions.
    Input: body message from broker
    Output = ip_add_list or Ip_del_list
    """
    message = json.loads(body)
    if message['state'] == True:
        ip_add_list = message['iplist']
        #print(ip_add_list)
        add_ip(ip_add_list)
        return True
    elif message['state'] == False:
        ip_del_list = message['iplist']
        #print(ip_del_list)
        delete_ip(ip_del_list)
        return True
    else:
        return False

if __name__ == '__main__':
    try:
        time.sleep(1)
        for i in db.getall():
            addr = netaddr.IPAddress(i)
            bl[bl.Key(addr)] = bl.Leaf(1)
        channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
        channel.start_consuming()
    except:
        print("Exit, Removing filter from device")
        for nic in device:
            b.remove_xdp(nic, 0)
            print(nic)
            time.sleep(10)
            exit()

channel.basic_consume(
    queue=queue_name, on_message_callback=callback, auto_ack=True)
channel.start_consuming()

