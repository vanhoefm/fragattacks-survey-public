import pandas
import time
import os
import sys
import numpy as np
import datetime
from scapy.layers.dot11 import Dot11AssoResp, Dot11Beacon, Dot11CCMP, Dot11Elt, Dot11EltHTCapabilities, Dot11EltRSN, Dot11EltRates, Dot11EltVendorSpecific, RadioTap
from scapy.layers.eap import EAP
from scapy.utils import hexdump
from tests import *


# Dataframe to save connected devices to a network
connectedDevices = pandas.DataFrame(columns=["ID", "BSSID", "MACDevice"])
connectedDevices.set_index("ID", inplace=True)

# Dataframe to save found networks
networks = pandas.DataFrame(columns=["ID", "BSSID", "SSID", "Channel", "Time", "Crypto", "RSN", "Rates", "HTCapabilities", "ESRates", "Enterprise", "WPS", "SignalStrength", "BeaconInterval", "MFPcapable", "MFPrequired", "pairwiseCiphers", "groupCiphers", "akm", "Vendor", "ouiList"])
networks.set_index("ID", inplace=True)

# Dataframe to save all the results of test executed on the networks
testedNetworks = pandas.DataFrame(columns=["ID", "BSSID", "SSID", "Channel", "Time", "Enterprise", "Crypto", "WPS", "SignalStrength", "BeaconCount", "BeaconInterval", "MFPcapable", "MFPrequired", "pairwiseCiphers", "groupCiphers", "akm", "Vendor", "ouiList", "connectedDevices"])
testedNetworks["AuthenticationDongle1"] = False
testedNetworks["AssociationDongle1"] = False
testedNetworks["AuthenticationDongle2"] = False
testedNetworks["AssociationDongle2"] = False
testedNetworks["eapol-amsdu"] = False
testedNetworks["eapol-forward"] = False
testedNetworks["plaintext-broadcast"] = False
testedNetworks["plaintext-fragmented-broadcast"] = False
testedNetworks["fragmentation-enterprise"] = False
testedNetworks["connected-device"] = False
testedNetworks.set_index("ID", inplace=True)

# List of channels that will be scanned
channels = [1, 6, 11]

# Wi-Fi dongles that are used for the scan
dongle1_inf = 'wlx24050f9e33dc'
dongle1_mac = '24:05:0f:9e:33:dc'

dongle2_inf = 'wlx24050f9e3454'
dongle2_mac = '24:05:0f:9e:34:54'

# OUI numbers detected only by one vendor in a Wi-Fi survey. Using this to help already finding the vendor.
vendor_dict = {
        16265956: "ASUSTek COMPUTER INC.",
        24672: "Alcatel-Lucent Enterprise",
        6130: "Apple, Inc.",
        915: "Apple, Inc.",
        20547: "Belkin International Inc.",
        558651: "Belkin International Inc.",
        6154: "Cisco Meraki",
        41208: "Extreme Networks, Inc.",
        6519: "Extreme Networks, Inc.",
        2319: "Fortinet, Inc.",
        16053736: "Google, Inc.",
        11306301: "Huawei Device Co., Ltd.",
        9480129: "Pakedge Device and Software Inc.",
        3138: "Routerboard.com",
        5010: "Ruckus Wireless",
        2795: "TP-LINK TECHNOLOGIES CO.,LTD.",
        12690: "TP-Link Corporation Limited",
        5485: "Ubiquiti Networks Inc."
    }


# variable to get the network that is currently tested. Needed to count beacon frames.
currentTestNetwork = ""

# Function that will be called on every received packet
def callback(packet):

    # Get beacon frames and put necessary information for authentication and association in a table
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2

        try:
            stats = packet[Dot11Beacon].network_stats()
            networkChannel = stats.get("channel")
            crypto = stats.get("crypto")


            # Count number of beacon frames of the network under test
            """
            if currentTestNetwork == bssid:testedNetworks
                count = testedNetworks.at[bssid, "BeaconCount"]
                testedNetworks.at[bssid, "BeaconCount"] = count + 1
            """
            # if not already in list of networks that has to be checked and (not in the list of networks already tested OR authentication and association was not successful)
            if not str(bssid) in networks.index.tolist() and channel == networkChannel:
                if ((not str(bssid) in testedNetworks.index.tolist()) or (testedNetworks.at[bssid, "AssociationDongle1"] == False
                                or testedNetworks.at[bssid, "AssociationDongle2"] == False
                                or testedNetworks.at[bssid, "AuthenticationDongle1"] == False
                                or testedNetworks.at[bssid, "AuthenticationDongle2"] == False)):

                    try:
                        ssid = packet[Dot11Elt].info.decode()
                    except:
                        print("ssiderror")
                        ssid = "ssidError"

                    print("Network is not in list and on the right channel, add it. channel: " + ssid)

                    if "_nomap" not in ssid and "optout" not in ssid:

                        # Extended Support Rates can be necessary for connection
                        esRates = False
                        if packet.haslayer(Dot11Elt):
                            dot11elt = packet.getlayer(Dot11Elt)
                            while dot11elt:
                                if dot11elt.ID == 50:
                                    esRates = dot11elt.info
                                dot11elt = dot11elt.payload.getlayer(Dot11Elt)
                        else:
                            esRates = False

                        if packet.haslayer(Dot11EltHTCapabilities):
                            htCapabilities = packet[Dot11EltHTCapabilities].info
                        else:
                            htCapabilities = False

                        enterprise = 0
                        # no rsn information => open Wi-Fi network
                        rsn = False
                        mfp_capable = False
                        mfp_required = False
                        pairwiseCiphers = []
                        groupCiphers = []
                        akm = []
                        if packet.haslayer(Dot11EltRSN):
                            rsn = raw(packet[Dot11EltRSN].info)
                            mfp_capable = packet[Dot11EltRSN].mfp_capable
                            mfp_required = packet[Dot11EltRSN].mfp_required
                            for el in packet[Dot11EltRSN].pairwise_cipher_suites:
                                pairwiseCiphers.append(el.cipher)
                            for el in packet[Dot11EltRSN].group_cipher_suite:
                                groupCiphers.append(el.cipher)
                            for el in packet[Dot11EltRSN].akm_suites:
                                akm.append(el.suite)

                            # More than 1 cipher, make a choice
                            if packet[Dot11EltRSN].nb_pairwise_cipher_suites > 1:
                                rsn = rsn[0:6] + b'\x01\x00' + rsn[8:12] + rsn[16:]

                            # A list of AKM suites, if it contains 802.1x, it is an enterprise network
                            nbAkmSuites = packet[Dot11EltRSN].nb_akm_suites
                            for i in range(0, nbAkmSuites):
                                if packet[Dot11EltRSN].akm_suites[i].suite == 1:
                                    enterprise = 1

                        rates = packet[Dot11EltRates].info

                        # Detect if WPS is enabled
                        wps = False
                        vendor = ""
                        ouiList = []
                        if packet.haslayer(Dot11EltVendorSpecific):
                            for x in packet[Dot11EltVendorSpecific].iterpayloads():
                                if x.haslayer(Dot11EltVendorSpecific):
                                    oui = x[Dot11EltVendorSpecific].oui
                                    ouiList.append(oui)  
                                    # Microsoft Corp. OUI:00:50:f2 -> decimal = 20722
                                    # Type WPS = \x04
                                    if oui == 20722 and raw(x[Dot11EltVendorSpecific])[5:6] == b'\x04':
                                        wps = True
                                    else:
                                        vendor = vendor_dict.get(oui, None)

                    signalStrength = packet[RadioTap].dBm_AntSignal

                    timeInterval = packet[Dot11Beacon].beacon_interval

                    now = datetime.now()
                    
                    networks.loc[bssid] = (bssid, ssid, networkChannel, str(now), crypto, rsn, rates, htCapabilities, esRates, enterprise, wps, signalStrength, timeInterval, mfp_capable, mfp_required, pairwiseCiphers, groupCiphers, akm, vendor, ouiList)


        except (TypeError, AttributeError) as e:
            print("Type Error: when retrieving the channel of the network")
            #excludedList.append(bssid)

    # check authentication dongle 1 & 2
    if packet.haslayer(Dot11Auth):
        if packet[Dot11].addr1 == dongle1_mac and packet[Dot11Auth].status == 0:
            testedNetworks.at[packet[Dot11].addr2, "AuthenticationDongle1"] = True

        if packet[Dot11].addr1 == dongle2_mac and packet[Dot11Auth].status == 0:
            testedNetworks.at[packet[Dot11].addr2, "AuthenticationDongle2"] = True

    # check association dongle 1
    if packet.haslayer(Dot11AssoResp):
        if packet[Dot11].addr1 == dongle1_mac and packet[Dot11AssoResp].status == 0:
            testedNetworks.at[packet[Dot11].addr2, "AssociationDongle1"] = True

        if packet[Dot11].addr1 == dongle2_mac and packet[Dot11AssoResp].status == 0:
            testedNetworks.at[packet[Dot11].addr2, "AssociationDongle2"] = True

    if packet.haslayer(Dot11):
        # check EAPOL Forward
        # <class 'scapy.packet.Padding'>
        if  packet[Dot11].addr1 == dongle2_mac and packet[Dot11].addr3 == dongle1_mac:
            print(Fore.GREEN + "FORWARDED PACKET CAPTURED" + Style.RESET_ALL)
            testedNetworks.at[packet[Dot11].addr2, "eapol-forward"] = True

        # check EAPOL AMSDU
        # For detection of this, there has to be a device connected previously to the network
        # addr1 = (RA=DA), addr2 = (TA=BSSID), addr3 = SA
        if packet[Dot11].addr1 == 'ff:ff:ff:ff:ff:ff' and packet[Dot11].addr3 == dongle1_mac:
            # can be from the AMSDU test, the plaintext test, or the fragmented plaintext test. (no addr3 would be different)
            print(Fore.GREEN + "BROADCAST PACKET CAPTURED" + Style.RESET_ALL)
            testedNetworks.at[packet[Dot11].addr2, "eapol-amsdu"] = True

        # check plaintext (fragmented) broadcast
        if packet[Dot11].addr1 == 'ff:ff:ff:ff:ff:ff' and packet[Dot11].addr2 in testedNetworks["BSSID"].tolist() :
            if packet[Dot11].addr3 in connectedDevices["MACDevice"].tolist() and packet.haslayer(Dot11CCMP):
                ## plaintext fragmented broadcast, data = 116 bytes
                ## plaintext broadcast, data = 84 bytes
                print(Fore.GREEN + "PLAINTEXT BROADCAST PACKET CAPTURED" + Style.RESET_ALL)
                print(len(raw(packet[Dot11CCMP])))

                if len(raw(packet[Dot11CCMP])) < 95:
                    testedNetworks.at[packet[Dot11].addr2, "plaintext-fragmented-broadcast"] = True
                else:
                    testedNetworks.at[packet[Dot11].addr2, "plaintext-broadcast"] = True


        # found a device that is connected to the network, necessary for ping to the server (valid mac and ip address)
        if packet[Dot11].addr1 in networks.index and packet[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" and packet[Dot11].addr2 != dongle1_mac and packet[Dot11].addr2 != dongle2_mac and packet[Dot11].addr2 != None and str(packet[Dot11].addr2[:8]) != '33:33:00' and str(packet[Dot11].addr2[:8]) != '01:00:5e' and str(packet[Dot11].addr2[:8]) != '01:80:c2':
            # Can not be removed because it is used in the detection
            connectedDevices.loc[packet[Dot11].addr1] = (packet[Dot11].addr1, packet[Dot11].addr2)
            plaintextTests(packet[Dot11].addr1, packet[Dot11].addr2)

        # found a device that is connected to the network, necessary for ping to the server (valid mac and ip address)
        if packet[Dot11].addr2 in networks.index and packet[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" and packet[Dot11].addr1 != dongle1_mac and packet[Dot11].addr1 != dongle2_mac and packet[Dot11].addr1 != None and  str(packet[Dot11].addr1[:8]) != '33:33:00' and str(packet[Dot11].addr1[:8]) != '01:00:5e' and str(packet[Dot11].addr1[:8]) != '01:80:c2':
            connectedDevices.loc[packet[Dot11].addr2] = (packet[Dot11].addr2, packet[Dot11].addr1)
            plaintextTests(packet[Dot11].addr2, packet[Dot11].addr1)

        # answer on an action frame, necessary for the fragmentation enterprise network test
        if packet[Dot11].type == 0 and packet[Dot11].subtype == 13 and packet[Dot11].addr1 == dongle1_mac and packet.haslayer(Raw):
            dialogToken = raw(packet[Raw])[2:3]

            # send directly after receiving an action frame
            frame = RadioTap() \
                / Dot11(type=0, subtype=13, addr1=packet[Dot11].addr2,
                        addr2=dongle1_mac, addr3=packet[Dot11].addr2) \
                / Raw(b'\x03\x01'  +  dialogToken  + b'\x00\x00\x03\x10\x00\x00')
            sendp(frame, iface=dongle1_inf)

        # check fragmentation enterprise network test
        if packet[Dot11].addr1 == dongle1_mac  and packet.haslayer(EAP):
            # FAILURE is eap_code == 4, mogelijk om er ook nog uit te halen
            # type is normaal EAP-TLS == 13
            if packet.getlayer(EAP).type != 1:
                print(Fore.GREEN + "PLAINTEXT FRAGMENTED, ENTERPRISE " + Style.RESET_ALL)
                testedNetworks.at[packet[Dot11].addr2, "fragmentation-enterprise"] = True

tested = []
def plaintextTests(router, device):
    if router not in tested:
        network = networks.loc[networks["BSSID"] == router].iloc[0]
        if network["BSSID"] not in testedNetworks.index.tolist():
            try:
                testedNetworks.loc[network["BSSID"]] = (network["BSSID"], network["SSID"], network["Channel"], str(network["Time"]), network["Enterprise"], str(network["Crypto"]),
                                                    network["WPS"], network["SignalStrength"],
                                                    0, network["BeaconInterval"], network["MFPcapable"], network["MFPrequired"], str(network["pairwiseCiphers"]),
                                                    str(network["groupCiphers"]), str(network["akm"]), str(network["Vendor"]),
                                                    str(network["ouiList"]), device, False, False, False, False, False, False, False, False, False, True)
            except(ValueError):
                print("problems with adding network")

        index = np.where(testedNetworks.index == router)[0]
        framesToSend = []
        #framesToSend += plaintextFragmented(router, device, index)
        #framesToSend += plaintext(router, device, index)
        framesToSend += plaintextBroadcast(router, device)
        framesToSend += plaintextBroadcastFragmented(router, device)
        sendp(framesToSend, iface=dongle1_inf)
        tested.append(router)



# Put the dongles in monitor mode
def setMonitorMode(inf):
    os.system("ifconfig " + inf + " down")
    os.system("iw " + inf + " set type monitor")
    os.system("ifconfig " + inf + " up")

if __name__ == "__main__":

    # set the dongles in monitor mode
    setMonitorMode(dongle1_inf)
    setMonitorMode(dongle2_inf)

    # start sniffing
    t = AsyncSniffer(iface=[dongle2_inf, dongle1_inf], filter="wlan type data or wlan type mgt", prn=callback, store=False)
    t.start()

    # make file for saving the times
    f = open("timesRounds.txt", "w")
    f.close()
    startRoundTime = 0

    try:
        while True:
            # scan the channels in the list
            for channel in channels:
                # measure time of a scan of all the channels
                if channel == min(channels):
                    startRoundTime = time.time()


                # Switch dongle's to new channels
                d2 = os.system(f"iwconfig {dongle2_inf} channel {channel}")
                d1 = os.system(f"iwconfig {dongle1_inf} channel {channel}")
                if d1 != 0 or d2 != 0:
                    # one of the interfaces isn't responding
                    print(Fore.RED + 'PROGRAM FORCED STOPPED!' + Style.RESET_ALL)
                    # print the testedNetworks in the terminal
                    print(testedNetworks)
                    # write the result to a csv file
                    testedNetworks.to_csv('testedNetworks.csv', escapechar='\\')
                    t.stop()
                    sys.exit(1)


                print("CHANGE CHANNEL: " + str(channel))
                time.sleep(0.4)
                testedNetworksIteration = []

                while not all(i in testedNetworksIteration for i in networks.index.tolist() ):

                    # Take a network that isn't checked
                    network = networks.loc[networks.index[0]]

                    #print("look at network: " + str(network["SSID"]))
                    # Don't test networks multiple times during one iteration
                    if network["BSSID"] not in testedNetworksIteration:
                        framesToSend = []

                        print("Network to be tested: " + str(network["SSID"] )+ " on channel: " + str(channel)+ " BSSID: " + str(network["BSSID"]))
                        # add network to the testedNetworks
                        try:
                            if network["BSSID"] not in testedNetworks.index.tolist():
                                testedNetworks.loc[network["BSSID"]] = (network["BSSID"], network["SSID"], network["Channel"], str(network["Time"]), network["Enterprise"], str(network["Crypto"]), network["WPS"], network["SignalStrength"],
                                                                        0, network["BeaconInterval"], network["MFPcapable"], network["MFPrequired"], str(network["pairwiseCiphers"]), str(network["groupCiphers"]), str(network["akm"]), str(network["Vendor"]),
                                                                        str(network["ouiList"]), "", False, False, False, False, False, False, False, False, False, False)
                            currentTestNetwork = network["BSSID"]

                            # authenticate and associate with the dongles
                            authenticationAssociation(dongle1_inf, dongle1_mac, network["SSID"], network["BSSID"], network["Rates"], network["RSN"], network["HTCapabilities"], network["ESRates"])
                            # authenticate and associate with the second dongle (send with dongle 1)
                            authenticationAssociation(dongle1_inf, dongle2_mac, network["SSID"], network["BSSID"], network["Rates"], network["RSN"], network["HTCapabilities"], network["ESRates"])

                            # generate frames for the fragmentation enterprise test
                            if network["Enterprise"] == 1:
                                framesToSend += fragmentationEnterprise(network["BSSID"], dongle1_inf, dongle1_mac)

                            # generate frames for EAPOL AMSDU test
                            framesToSend += eapolAmsdu(network["BSSID"], dongle1_inf, dongle1_mac)
                            # generate frames for EAPOL Forward test
                            framesToSend += eapolForward(network["BSSID"], dongle1_inf, dongle1_mac, dongle2_mac)

                            sendp(framesToSend, iface=dongle1_inf)

                            # remove network from the networks still need to be tested
                            networks = networks.drop(network["BSSID"])

                            testedNetworksIteration.append(network["BSSID"])
                            currentTestNetwork = ""
                        except(ValueError):
                            print("print problems with adding to database 2")
                    else:
                        # Network was already tested remove it
                        print("remove network")
                        networks = networks.iloc[1:, :]

                """
                # Generate list with connected devices and the corresponding router mac addresses
                macList = []
                routerMacList = []
                indexList = []
                for index, row in connectedDevices.iterrows():
                    macList.append(row["MACDevice"])
                    routerMacList.append(row["BSSID"])
                    testedNetworks.at[row["BSSID"], "connected-device"] = True
                    testedNetworks.at[row["BSSID"], "connectedDevices"] = row['MACDevice']
                    i = np.where(testedNetworks.index == row["BSSID"])[0]
                    indexList.append(i)

                framesToSend = []

                # fragmented palintext ping to server
                #framesToSend += plaintextFragmented(routerMacList, macList, dongle1_inf, indexList)
                # plaintext ping to server
                #framesToSend += plaintext(routerMacList, macList, dongle1_inf, indexList)

                # test if the router accept plaintext frames (test by broadcast)
                framesToSend += plaintextBroadcast(routerMacList, macList, dongle1_inf)


                # test if the router accept fragmented plaintext frames (test by broadcast)
                framesToSend += plaintextBroadcastFragmented(routerMacList, macList, dongle1_inf)

                #framesToSend += eapolAmsduValidSenderMac(routerMacList, macList, dongle1_inf)

                sendp(framesToSend, iface=dongle1_inf)
                """

                # some time for the sniffer to get the answers on the current channel
                time.sleep(1)


                # empty the dataframe, possible that soms networks where detected but aren't on the right channel
                networks = networks[0:0]
                connectedDevices = connectedDevices[0:0]

                # write results to file as backup
                if channel == max(channels):
                    testedNetworks.to_csv('testedNetworks.csv', escapechar='\\')

                    stopRoundTime = time.time()
                    f = open("timesRounds.txt", "a")
                    f.write(str(stopRoundTime - startRoundTime) + "\n")
                    f.close()


    # exit te program with ctrl -c
    except KeyboardInterrupt:
        print(Fore.RED + 'PROGRAM STOPPED!' + Style.RESET_ALL)
        # some time for the last responses to arrive
        time.sleep(2)

        # print the testedNetworks in the terminal
        print(testedNetworks)
        # write the result to a csv file
        testedNetworks.to_csv('testedNetworks.csv', escapechar='\\')
        t.stop()