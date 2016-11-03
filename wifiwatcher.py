#! /usr/bin/env python

#Author: Michael Littley
#File: wifiwatcher
#version 1.0
#Detects broadcast deauthentication attacks

from scapy.all import *
from multiprocessing import Process, Queue
import time
import argparse
import re

#Global variables needed for action
global alertQueue
global bssid

def action(packet):
    try:
        if (packet.type == 0) and  \
            (packet.subtype == 12) and \
            (packet.addr1 == 'ff:ff:ff:ff:ff:ff') and \
            (packet.addr2 == bssid):
            alertQueue.put(1)
    except:
        pass
        

def sniffTraffic():
    sniff(prn=action)

def timeout():
    time.sleep(1)
    alertQueue.put(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
                                    'watches for deauthentication attacks')
    parser.add_argument('-bssid', dest='bssid', required=True,
                        help='MAC address of Router to watch')
    args = parser.parse_args()

    bssid = args.bssid.strip()
    if not re.match('^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]){2}$', bssid):
        print "bssid must be MAC address: format: [00:ff]:[00:ff]:[00:ff]:[00:ff]:[00:ff]:[00:ff]"
        quit()

    alertQueue = Queue()
    sniffer = Process(target=sniffTraffic)
    sniffer.start()
    
    attack = False
    count = 0
    timer = Process()
    while True:
        msg = alertQueue.get()
        if msg == 1:
            if attack == False:
                attack = True
                if count == 0:
                    print "broadcast deauthentication packet detected from router"
                if not timer.is_alive():
                    timer = Process(target=timeout)
                    timer.start()
            count += 1
        elif msg == 0:
            timer.join()
            if alertQueue.empty():
                if  attack == True:
                    attack = False
                    timer = Process(target=timeout)
                    timer.start()
                else:
                    print "deauthentication ended,", count, "deauthentication packets were detected"
                    count = 0
            else:
                timer = Process(target=timeout)
                timer.start()
