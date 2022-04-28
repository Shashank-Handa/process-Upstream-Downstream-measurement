
import socket
import sys

#import psutil
import pyshark
import os
import subprocess

ipAddr="10.0.2.5"
interface_name='any'
filter_string='src host 10.0.2.5 or dst host 10.0.2.5'

"""def get_pid(port):
    connections = psutil.net_connections()
    for con in connections:
        if con.raddr.port == port:
            return con.pid
        if con.laddr.port == port:
            return con.pid
    return -1"""

"""def get_pid(port):
    print("called")
    for process in psutil.process_iter():
        for conns in process.connections(kind='inet'):
            if conns.laddr.port == port:
                print(process.name())
                return process.name()"""


def get_pid(port):
    process=subprocess.Popen(["lsof","-i",":{0}".format(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderrr = process.communicate()
    for process in str(stdout.decode("utf-8")).split("/n")[1:]:
        data=[x for x in process.split(" ") if x!= '']
        if(len(data)<=1):
            continue
        print(data)
        return data[0]

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
