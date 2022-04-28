import subprocess
from psutil import *

def myFunc():
    i=0
    for process in process_iter():
        
        for conn in process.connections("all"):
            if(conn.laddr.port==137):
                print(process.name())
                print(conn.laddr.port)
        i+=1
        if(i>10):
            break
    return

def get_pid(port):
    print("called")
    for process in process_iter():
        for conns in process.connections("all"):
            if conns.laddr.port == port:
                print(process.name())

myFunc()
get_pid(137)
