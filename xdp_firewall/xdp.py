#!/usr/bin/python3

from bcc import BPF
from configs import device, api_secreckey
from flask import Flask, request
import netaddr, pickledb, time


app = Flask(__name__)
db = pickledb.load('iplist.db', False)
device = device
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
b.attach_xdp(device, fn, 0)
bl = b["blacklist"]


@app.route('/add', methods=['POST', 'GET'])
def add_ip():
    temp_key = request.headers.get(key='x_key_auth')
    if temp_key == api_secreckey and request.method == 'POST':
        message = ""
        data = request.get_json()
        for i in data.keys():
            ipaddr = netaddr.IPAddress(i)
            db.set(str(ipaddr), str(data[i]))
            bl[bl.Key(ipaddr)] = bl.Leaf(1)
        db.dump()
        return message, 201
    
    # Get list on ip block
    elif temp_key == api_secreckey and request.method == 'GET':
        data = db.getall()
        return str(data)
    else:
        return "", 503


@app.route('/del', methods=['POST',])
def delete_ip():
    temp_key = request.headers.get(key='x_key_auth')
    if temp_key == api_secreckey and request.method == 'POST':
        message = ""
        data = request.get_json()
        for i in data.keys():
                
            ipaddr = netaddr.IPAddress(i)
            del bl[bl.Key(ipaddr)]
            db.rem(str(ipaddr))
            db.dump()
        return message, 201
    else:
        return "", 503


if __name__ == '__main__':
    try:
        time.sleep(1)
        for i in db.getall():
            addr = netaddr.IPAddress(i)
            bl[bl.Key(addr)] = bl.Leaf(1)
        app.run()
    except KeyboardInterrupt:
        print("Removing filter from device")

b.remove_xdp(device, 0)
