
import pyshark
import socket
import psutil
import sys

ipAddr="10.0.2.5"
interface_name='any'
filter_string='src host 10.0.2.5 or dst host 10.0.2.5'

def get_pid(port):
    connections = psutil.net_connections()
    for con in connections:
        if con.raddr[1] == port:
            return con.pid
        elif con.laddr[1] == port:
            return con.pid
    return -1

capture=pyshark.LiveCapture(
    bpf_filter=filter_string,
    interface=interface_name
)

capture.sniff(packet_count=10)


downStream={}
upStream={}

if(len(capture)>0):
    for packet in capture:
        protocol=packet.transport_layer
        if(packet.ip.src==ipAddr):
            print("up")
            if(packet[protocol].srcport in upStream):
                upStream[packet[protocol].srcport][0]+=int(packet.length)
            else:
                upStream[packet[protocol].srcport]=[int(packet.length)]
                upStream[packet[protocol].srcport].append(get_pid(packet[protocol].srcport))
        if(packet.ip.dst==ipAddr):
            print("down")
            if(packet[protocol].dstport in downStream):
                downStream[packet[protocol].dstport][0]+=int(packet.length)
            else:
                downStream[packet[protocol].dstport]=[int(packet.length)]
                downStream[packet[protocol].dstport].append(get_pid(packet[protocol].dstport))
    print(downStream)
    print(upStream)




