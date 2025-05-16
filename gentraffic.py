#!/usr/bin/env python3
import time
from scapy.all import *

conf.iface = "wlan2"

while True: 
	time.sleep(0.5) 
	sendp(Ether(dst="02:00:00:00:03:00", src="02:00:00:00:02:00")/IP()/DNS())

