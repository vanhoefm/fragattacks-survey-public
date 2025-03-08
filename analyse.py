## Script to make an analysis from the received data from the Wi-Fi survey

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from IPython.display import display
import xml.etree.ElementTree as ET

folder = "Survey 2025"

# import time files
f = open( './' + folder + '/Data/timesRoundsCombined.txt','r')
lines = f.read().splitlines()
f.close()

# import dataframe
df = pd.read_csv('./' + folder + '/Data/testedNetworksCombined.csv')
df = df[df['Crypto'].notna()]


# Signal strength analysis
hist = df.hist(column='SignalStrength', bins=20)
plt.title('Ontvangen signaalsterkte')
plt.xlabel('Signaalsterkte (dBm)')
plt.ylabel('Aantal netwerken')
plt.savefig('./' + folder +'/signalStrength.pdf')

# make an output file
out = open('./'+ folder + '/analyse.txt', 'w')

## Time Rounds analyse
# graph of times necessary for a full channel hop
x = []
y = []
total = 0
for i in range(0, len(lines)):
    x.append(i)
    y.append(round(float(lines[i]),2))
    total += float(lines[i])

average = total/(len(lines))
plt.plot([0, (len(lines)-1)], [average, average], color='red')
plt.plot(x, y)
plt.xlabel('Iteration number')
plt.ylabel('Time in seconds')
plt.title('Time to complete one iteration of the 13 channels')
plt.savefig('./' + folder +'/timesRounds.pdf')
#plt.show()
plt.clf()

# write to .txt file
out.write('Time necessary to complete a run over the 13 channels: ' + '\n')
out.write('Average time: ' + str(average) + '\n\n')


## Channel analyse
# write to .txt file
occur = df.groupby(['Channel']).size()
out.write('Distribution of networks over the channels: ' + '\n')
out.write(str(occur) + '\n\n')

# make histogram
bins = range(1,15)
plt.hist(df["Channel"], bins=bins, align='left')
plt.xticks(list(range(1,14)))
plt.title('Verdeling van netwerken over de channels')
plt.xlabel('Channels')
plt.ylabel('Aantal netwerken')
plt.savefig('./' + folder +'/channels.pdf')
#plt.show()
plt.clf()

## Association analyse
# write to .txt file
numberOfNetworks = len(df.index)
out.write('Number of networks found: ' + '\n')
out.write(str(numberOfNetworks) + '\n\n')

authenticationAssociationDongle1Count =len(df[(df["AuthenticationDongle1"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where authentication and association was successful with Dongle1: ' + '\n')
out.write(str(authenticationAssociationDongle1Count) + '\n')

authenticationDongle1Count = ( df["AuthenticationDongle1"] == True).sum()
out.write('Number of networks authentication was successful with Dongle1: ' + '\n')
out.write(str(authenticationDongle1Count) + '\n')

associationDongle1Count = (df["AssociationDongle1"] == True).sum()
out.write('Number of network association was successful with Dongle1: ' + '\n')
out.write(str(associationDongle1Count) + '\n')

authenticationFalseAssociationDongle1Count = len(df[(df["AuthenticationDongle1"] == False) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where authentication was unsuccessful and association was successful with Dongle1: ' + '\n')
out.write(str(authenticationFalseAssociationDongle1Count) + '\n\n')


authenticationAssociationDongle2Count = len(df[(df["AuthenticationDongle2"] == True) & (df["AssociationDongle2"] == True)])
out.write('Number of networks where authentication and association was successful with Dongle2: ' + '\n')
out.write(str(authenticationAssociationDongle2Count) + '\n')

authenticationDongle2Count = ( df["AuthenticationDongle2"] == True).sum()
out.write('Number of networks authentication was successful with Dongle2: ' + '\n')
out.write(str(authenticationDongle2Count) + '\n')

associationDongle2Count = (df["AssociationDongle2"] == True).sum()
out.write('Number of network association was successful with Dongle2: ' + '\n')
out.write(str(associationDongle2Count) + '\n')

authenticationFalseAssociationDongle2Count = len(df[(df["AuthenticationDongle2"] == False) & (df["AssociationDongle2"] == True)])
out.write('Number of networks where authentication was unsuccessful and association was successful with Dongle2: ' + '\n')
out.write(str(authenticationFalseAssociationDongle2Count) + '\n\n')

authenticationAssociationDonglesCount = len(df[(df["AuthenticationDongle2"] == True) & (df["AssociationDongle2"] == True) & (df["AuthenticationDongle1"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where authentication and association was successful with both dongles: ' + '\n')
out.write(str(authenticationAssociationDonglesCount) + '\n\n')

associationDonglesCount = len(df[ (df["AssociationDongle2"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where association was successful with both dongles: ' + '\n')
out.write(str(associationDonglesCount) + '\n\n')



eapolAmsdu = (df["eapol-amsdu"] == True).sum()
eapolAmsduDongle1 = len(df[(df["eapol-amsdu"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks vulnerable for the EAPOL-AMSDU attack: ' + '\n')
out.write(str(eapolAmsdu) + '\n')
out.write(str(eapolAmsdu/numberOfNetworks*100) + '%\n')
out.write('Number of networks vulnerable for the EAPOL-AMSDU attack and where dongle 1 is fully associated: ' + '\n')
out.write(str(eapolAmsduDongle1) + '\n')
out.write('Divided by networks were dongle1 was successfully associated: ' + '\n')
out.write(str(eapolAmsduDongle1/associationDongle1Count*100) + '%\n\n')

eapolForward = (df["eapol-forward"] == True).sum()
eapolForwardDongles = len(df[(df["eapol-forward"] == True) & (df["AssociationDongle1"] == True) & (df["AssociationDongle2"] == True)])
out.write('Number of networks vulnerable for the EAPOL forward attack: ' + '\n')
out.write(str(eapolForward) + '\n')
out.write(str(eapolForward/numberOfNetworks*100) + '%\n')
out.write('Number of networks vulnerable for the EAPOL-forward attack and where dongle1 and dongle2 are fully associated: ' + '\n')
out.write(str(eapolForwardDongles) + '\n')
out.write('Divided by networks were dongle1 and dongle2 were successfully associated: ' + '\n')
out.write(str(eapolForwardDongles/associationDonglesCount*100) + '%\n\n')


connectedDevices = (df["connected-device"] == True).sum()
connectedDevicesDongle1 = len(df[(df["connected-device"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where a connected device was detected: ' + '\n')
out.write(str(connectedDevices) + '\n')
out.write(str(connectedDevices/numberOfNetworks*100) + '%\n\n')

plaintextBroadcast = len(df[(df["connected-device"] == True) & (df["plaintext-broadcast"] == True)])
plaintextBroadcastDongle1 = len(df[(df["connected-device"] == True) & (df["plaintext-broadcast"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the plaintext broadcast attack: ' + '\n')
out.write(str(plaintextBroadcast) + '\n')
out.write(str(plaintextBroadcast/connectedDevices*100) + '%\n')
out.write('Number of networks where a device is connected, dongle1 fully associated and are vulnerable to the plaintext broadcast attack: ' + '\n')
out.write(str(plaintextBroadcastDongle1) + '\n')
out.write('Divided by networks were dongle1 was successfully associated: ' + '\n')
out.write(str(plaintextBroadcastDongle1/connectedDevicesDongle1*100) + '%\n\n')

# comment next block when without ping
"""
plaintextPing = len(df[(df["connected-device"] == True) & (df["plaintext-ping"] == True)])
plaintextPingDongle1 = len(df[(df["connected-device"] == True) & (df["plaintext-ping"] == True)  & (df["AssociationDongle1"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the plaintext ping attack: ' + '\n')
out.write(str(plaintextPing) + '\n')
out.write(str(plaintextPing/connectedDevices*100) + '%\n')
out.write('Number of networks where a device is connected, dongle1 fully associated and are vulnerable to the plaintext ping attack: ' + '\n')
out.write(str(plaintextPingDongle1) + '\n')
out.write('Divided by networks were dongle1 was successfully associated: ' + '\n')
out.write(str(plaintextPingDongle1/connectedDevicesDongle1*100) + '%\n\n')
"""
# until here

plaintextFragmentedBroadcast = len(df[(df["connected-device"] == True) & (df["plaintext-fragmented-broadcast"] == True)])
plaintextFragmentedBroadcastDongle1 = len(df[(df["connected-device"] == True) & (df["plaintext-fragmented-broadcast"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the plaintext fragmented broadcast attack: ' + '\n')
out.write(str(plaintextFragmentedBroadcast) + '\n')
out.write(str(plaintextFragmentedBroadcast/connectedDevices*100) + '%\n')
out.write('Number of networks where a device is connected, dongle1 is assoicated and are vulnerable to the plaintext fragmented broadcast attack: ' + '\n')
out.write(str(plaintextFragmentedBroadcastDongle1) + '\n')
out.write('Divided by networks were dongle1 was successfully associated: ' + '\n')
out.write(str(plaintextFragmentedBroadcastDongle1/connectedDevicesDongle1*100) + '%\n\n')

# comment next block when without ping
"""
plaintextFragmentedPing = len(df[(df["connected-device"] == True) & (df["plaintext-fragmented-ping"] == True)])
plaintextFragmentedPingDongle1 = len(df[(df["connected-device"] == True) & (df["plaintext-fragmented-ping"] == True)  & (df["AssociationDongle1"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the plaintext fragmented ping attack: ' + '\n')
out.write(str(plaintextFragmentedPing) + '\n')
out.write(str(plaintextFragmentedPing/connectedDevices*100) + '%\n')
out.write('Number of networks where a device is connected, dongle1 is assoicated and are vulnerable to the plaintext fragmented ping attack: ' + '\n')
out.write(str(plaintextFragmentedPingDongle1) + '\n')
out.write('Divided by networks were dongle1 was successfully associated: ' + '\n')
out.write(str(plaintextFragmentedPingDongle1/connectedDevicesDongle1*100) + '%\n\n')

plaintextPing = len(df[(df["connected-device"] == True) & (df["plaintext-ping"] == True) & (df["plaintext-broadcast"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the plaintext attack, detected with broadcast and ping: ' + str(plaintextPing) + '\n')
plaintextFragmentedPing = len(df[(df["connected-device"] == True) & (df["plaintext-fragmented-ping"] == True) & (df["plaintext-fragmented-broadcast"] == True)])
out.write('Number of networks where a device is connected and are vulnerable to the fragmented plaintext attack, detected with broadcast and ping: ' + str(plaintextFragmentedPing) + '\n\n')
"""
# until here

enterprise = (df["Enterprise"] == True).sum()
authenticationAssociationDongle1CountEnterprise =len(df[ (df["AssociationDongle1"] == True) & (df["Enterprise"] == True)])

out.write('Number of enterprise networks: ' + '\n')
out.write(str(enterprise) + '\n')
out.write(str(enterprise/numberOfNetworks*100) + '%\n')

fragmentationEnterprise = len(df[(df["Enterprise"] == True) & (df["fragmentation-enterprise"] == True)])
fragmentationEnterpriseDongle1 = len(df[(df["Enterprise"] == True) & (df["fragmentation-enterprise"] == True) & (df["AssociationDongle1"] == True)])
out.write('Number of enterprise networks that are vulnerable to the fragmentation attack: ' + '\n')
out.write(str(fragmentationEnterprise) + '\n')
out.write(str(fragmentationEnterprise/enterprise*100) + '%\n')
out.write('Number of enterprise networks were dongle1 is fully associated and are vulnerable to the fragmentation attack: ' + '\n')
out.write(str(fragmentationEnterpriseDongle1) + '\n')
out.write('Divided by networks were dongle1 was associated connected: ' + '\n')
out.write(str(fragmentationEnterpriseDongle1/authenticationAssociationDongle1CountEnterprise*100) + '%\n\n')

totalVulnerableNetworks = len(df[(df["eapol-amsdu"] == True) | (df["eapol-forward"] == True) | (df["plaintext-broadcast"] == True) | (df["plaintext-fragmented-broadcast"] == True) | (df["fragmentation-enterprise"] == True) | (df["plaintext-fragmented-broadcast"] == True) ])
totalVulnerableNetworksWPS = len(df[(df["WPS"] == True) & ((df["eapol-amsdu"] == True) | (df["eapol-forward"] == True) | (df["plaintext-broadcast"] == True) | (df["plaintext-fragmented-broadcast"] == True) | (df["fragmentation-enterprise"] == True) | (df["plaintext-fragmented-broadcast"] == True) )])
totalVulnerableNetworksDongle1 = len(df[(df["AssociationDongle1"] == True) & ((df["eapol-amsdu"] == True) | (df["eapol-forward"] == True) | (df["plaintext-broadcast"] == True) | (df["plaintext-fragmented-broadcast"] == True) | (df["fragmentation-enterprise"] == True) | (df["plaintext-fragmented-broadcast"] == True))])
totalVulnerableNetworksWPSDongle1 = len(df[(df["WPS"] == True) & (df["AssociationDongle1"] == True) & ((df["eapol-amsdu"] == True) | (df["eapol-forward"] == True) | (df["plaintext-broadcast"] == True) | (df["plaintext-fragmented-broadcast"] == True) | (df["fragmentation-enterprise"] == True) | (df["plaintext-fragmented-broadcast"] == True) )])
wpsAndAssociationDongle1 = len(df[(df['WPS'] == True) & (df["AssociationDongle1"] == True)])

# WPS analysis
WPS = (df["WPS"] == True).sum()
noWPS = (df["WPS"] == False).sum()

out.write('WPS: ' + '\n')
out.write('WPS: ' + str(WPS) + '\n')
out.write(str(WPS/numberOfNetworks*100) + '%\n')
out.write('noWPS: ' + str(noWPS) + '\n')
out.write(str(noWPS/numberOfNetworks*100) + '%\n\n')

out.write('Total of vulnerable networks ' + str(totalVulnerableNetworks) + '\n')
out.write('Total of vulnerable networks with WPS ' + str(totalVulnerableNetworksWPS) + '\n')
out.write('Total of vulnerable networks and Dongle 1 is associated ' + str(totalVulnerableNetworksDongle1) + '\n')
out.write('Total of vulnerable networks with WPS and Dongle 1 is associated' + str(totalVulnerableNetworksWPSDongle1) + '\n')
out.write('Networks were WPS is activated and Association with dongle 1 was successful ' + str(wpsAndAssociationDongle1) + '\n\n')



# Signal strength analysis
hist = df.hist(column='SignalStrength', bins=20)
plt.title('Ontvangen signaal sterkte')
plt.xlabel('Signaal sterkte (dBm)')
plt.ylabel('Aantal netwerken')
plt.savefig('./' + folder +'/signalStrength.pdf')

# Crypto analysis
occur = df.groupby(['Crypto']).size()
out.write('Crypto: ' + '\n')
out.write(str(occur) + '\n\n')


# MFP capable and required analysis
MFPcapable = (df["MFPcapable"] == "1").sum()
MFPrequired = (df["MFPrequired"] == "1").sum()
MFPreqAndCap = len(df[(df["MFPcapable"] == "1") & (df["MFPrequired"] == "1")])
out.write('MFP capable: ' + str(MFPcapable) + ", " +  str(MFPcapable/numberOfNetworks*100) + '%\n')
out.write('MFP required: ' + str(MFPrequired) + ", " + str(MFPrequired/numberOfNetworks*100) + '%\n')
out.write('MFP capable and required: ' + str(MFPreqAndCap) + ", " + str(MFPreqAndCap/numberOfNetworks*100)+ '%\n\n')

# Cipher analysis
## Pairwise
occur = df.groupby(['pairwiseCiphers']).size()
out.write('pairwise ciphers: ' + '\n')
out.write(str(occur) + '\n\n')

## GroupCipher
occur = df.groupby(['groupCiphers']).size()
out.write('group ciphers: ' + '\n')
out.write(str(occur) + '\n\n')

# AKM suite
occur = df.groupby(['akm']).size()
out.write('akm: ' + '\n')
out.write(str(occur) + '\n\n')

# Vendors analysis

# comment when using ping tests
vendors = pd.DataFrame(columns=["ID", "BSSID", "SSID", "VendorMAC", "VendorName", "Vulnerable", "NumberOfDevices", "ouiList", "WPS", "MFPcapable", "MFPreqAndCap",
                                "associationDongle1", "eapol-amsdu", "eapol-amsduVW", "associationDongle1en2", "eapol-forward", "eapol-forwardVW",
                                "associationDongle1AndDevice", "plaintext-broadcast", "plaintext-broadcastVW", "plaintext-fragmented-broadcast", "plaintext-fragmented-broadcastVW",
                                "enterprise", "enterpriseAssociationDongle1", "fragmentation-enterprise", "fragmentation-enterpriseVW"])
"""
vendors = pd.DataFrame(columns=["ID", "BSSID", "SSID", "VendorMAC", "VendorName", "Vulnerable", "NumberOfDevices", "ouiList", "WPS", "MFPcapable", "MFPreqAndCap",
                                "associationDongle1", "eapol-amsdu", "eapol-amsduVW", "associationDongle1en2", "eapol-forward", "eapol-forwardVW",
                                "associationDongle1AndDevice", "plaintext-broadcast", "plaintext-broadcastVW", "plaintext-fragmented-broadcast", "plaintext-fragmented-broadcastVW",
                                "plaintext-ping", "plaintext-pingVW", "plaintext-fragmented-ping", "plaintext-fragmented-pingVW",
                                "enterprise", "enterpriseAssociationDongle1", "fragmentation-enterprise", "fragmentation-enterpriseVW"])
"""
vendors.set_index("ID", inplace=True)

#ven = {'ID': df['ID'], 'BSSID': df['BSSID'], 'Vendor': df["BSSID"].apply(lambda x: str(x)[0:8])}

# comment this line and uncomment following when working with time
ven = df[['ID', 'BSSID']]
#ven = df[['ID', 'BSSID', 'Time']]

ven['Vendor'] = ven["BSSID"].apply(lambda x: str(x)[0:8])
ven.set_index("ID", inplace=True)
print("lengte ven: " + str(len(ven)))

#comment next line when working with time
local = pd.DataFrame(columns=["ID", "BSSID",  "VendorMAC", "VendorName","SSID", "NumberOfDevices"])
#local = pd.DataFrame(columns=["ID", "BSSID",  "VendorMAC", "VendorName","SSID", "NumberOfDevices", "Time"])

local.set_index("ID", inplace=True)

# list from https://devtools360.com/en/macaddress/vendorMacs.xml
tree = ET.parse('vendorMacs.xml')
root = tree.getroot()

# Normal networks
for index, row in ven.iterrows():
    vendorName = df[df["BSSID"] == index]["Vendor"].values[0]
    res = bin(int(str(row['Vendor'])[0:2], 16))

    dataframeRow = df.loc[df['BSSID'] == row['BSSID']].iloc[0]

    # if it is a local network, add it to the local dataset
    if res[-2] == "1":
        networkName = df.loc[df['BSSID'] == row['BSSID']]["SSID"]
        # comment next line and uncomment the other when working with time
        local.loc[row['BSSID']] = (row['BSSID'], row['Vendor'], vendorName, networkName.values[0],1)
        #local.loc[row['BSSID']] = (row['BSSID'], row['Vendor'], vendorName, networkName.values[0],1, dataframeRow['Time'])
    else:
        # if vendor name is already found, take it
        if row['BSSID'][:8] in vendors.index.tolist():
            vendorName = vendors.loc[i[:8]]['VendorName']
        # vendor name is not already found, find it in the database
        if str(vendorName) == "nan":
            for ve in root.findall("{http://www.cisco.com/server/spt}VendorMapping"):
                vendorMac = ve.get('mac_prefix')
                if vendorMac == row['Vendor'].upper():
                    vendorName = ve.get('vendor_name')
                    break;

        vulnerable = 0
        if (dataframeRow["eapol-amsdu"] == True) | (dataframeRow["eapol-forward"] == True) | (
                dataframeRow["plaintext-broadcast"] == True) | (
                dataframeRow["plaintext-fragmented-broadcast"] == True) | (
                dataframeRow["fragmentation-enterprise"] == True):
            vulnerable = 1
        assocDongle1en2 = 0
        if dataframeRow['AssociationDongle2'] == True and dataframeRow['AssociationDongle1'] == True:
            assocDongle1en2 = 1
        assocDongle1enDevice = 0
        if dataframeRow['AssociationDongle1'] == True and dataframeRow['connected-device'] == True:
            assocDongle1enDevice = 1

        eapolAmsduVW = 0
        if dataframeRow['eapol-amsdu'] == True and dataframeRow['AssociationDongle1'] == True:
            eapolAmsduVW = 1
        eapolForwardVW = 0
        if dataframeRow['eapol-forward'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow['AssociationDongle2'] == True:
            eapolForwardVW = 1
        plaintextBroadcastVW = 0
        if dataframeRow['plaintext-broadcast'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow['connected-device'] == True:
            plaintextBroadcastVW = 1
        plaintextFragmentedBroadcastVW = 0
        if dataframeRow['plaintext-fragmented-broadcast'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow['connected-device'] == True:
            plaintextFragmentedBroadcastVW = 1

        # added for ping
        """
        plaintextPingVW = 0
        if dataframeRow['plaintext-ping'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow[
            'connected-device'] == True:
            plaintextPingVW = 1
        plaintextFragmentedPingVW = 0
        if dataframeRow['plaintext-fragmented-ping'] == True and dataframeRow['AssociationDongle1'] == True and \
                dataframeRow['connected-device'] == True:
            plaintextFragmentedPingVW = 1
	"""
        fragmentationEnterpriseVW = 0
        if dataframeRow['fragmentation-enterprise'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow['Enterprise'] == True:
            fragmentationEnterpriseVW = 1
        enterpriseAndAssociationDongle1 = 0
        if dataframeRow['AssociationDongle1'] == True and dataframeRow['Enterprise'] == True:
            enterpriseAndAssociationDongle1 = 1

        # add row to dataframe
        if str(vendorName) == "nan":
            vendorName = "Not Found"
        vendors.loc[row['BSSID']] = (row['BSSID'], dataframeRow['SSID'],
                                     row['Vendor'], vendorName, vulnerable, 1,dataframeRow['ouiList'],  1 if dataframeRow['WPS'] else 0,
                                     1 if dataframeRow['MFPcapable']=="1" else 0, 1 if dataframeRow['MFPrequired'] =="1" else 0,
                                     1 if dataframeRow['AssociationDongle1'] else 0,
                                     1 if dataframeRow['eapol-amsdu'] else 0, eapolAmsduVW, assocDongle1en2,
                                     1 if dataframeRow['eapol-forward'] else 0, eapolForwardVW, assocDongle1enDevice,
                                     1 if dataframeRow['plaintext-broadcast'] else 0, plaintextBroadcastVW,
                                     1 if dataframeRow['plaintext-fragmented-broadcast'] else 0, plaintextFragmentedBroadcastVW,
                                     #1 if dataframeRow['plaintext-ping'] else 0, plaintextPingVW,
                                     #1 if dataframeRow['plaintext-fragmented-ping'] else 0, plaintextFragmentedPingVW,
                                     1 if dataframeRow['Enterprise'] else 0, enterpriseAndAssociationDongle1,
                                     1 if dataframeRow['fragmentation-enterprise'] else 0, fragmentationEnterpriseVW
                                     )

# get the vendors of some big companies
vendorsTelenetWiFreeCertain = []
vendorsProximusPublicCertain = []
vendorsOrangeGuestCertain = []
vendorsTelenetCertain = []
vendorsProximusCertain = []
vendorsOrangeCertain = []
for index, row in vendors.iterrows():
    ssid = df.loc[df['BSSID'] == row['BSSID']].iloc[0]['SSID']
    if 'TelenetWiFree' in str(ssid):
        vendorsTelenetWiFreeCertain.append(row['VendorName'])
    if 'Proximus Public Wi-Fi' in str(ssid):
        vendorsProximusPublicCertain.append(row['VendorName'])
    if 'Guest-Orange' in str(ssid):
        vendorsOrangeGuestCertain.append(row['VendorName'])
    if 'telenet' in str(ssid).lower():
        vendorsTelenetCertain.append(row['VendorName'])
    if 'proximus' in str(ssid).lower():
        vendorsProximusCertain.append(row['VendorName'])
    if 'orange' in str(ssid).lower():
        vendorsOrangeCertain.append(row['VendorName'])
vendorsTelenetWiFreeCertain = list(dict.fromkeys(vendorsTelenetWiFreeCertain))
vendorsProximusPublicCertain = list(dict.fromkeys(vendorsProximusPublicCertain))
vendorsOrangeGuestCertain = list(dict.fromkeys(vendorsOrangeGuestCertain))
vendorsTelenetCertain = list(dict.fromkeys(vendorsTelenetCertain))
vendorsProximusCertain = list(dict.fromkeys(vendorsProximusCertain))
vendorsOrangeCertain = list(dict.fromkeys(vendorsOrangeCertain))

telenetCertain = vendors.loc[(vendors['SSID'].str.contains('telenet', case=False, na=False))]
proximusCertain = vendors.loc[vendors['SSID'].str.contains('proximus', case=False, na=False)]
orangeCertain = vendors.loc[vendors['SSID'].str.contains('orange', case=False, na=False)]


# Local networks
print("start local")
for index, row in local.iterrows():
    vendorName = df[df["BSSID"] == index]["Vendor"].values[0]
    if str(vendorName) == "nan":
        vendorName = "local"

        # flip local bit, maybe another network were just this bit is flipped
        binair = bin(int(row['VendorMAC'][0:2], 16))
        flipped = binair[:-2] + "0" + binair[-1]
        flipped2 = binair[:-3] + "00" + binair[-1]
        hex1 = hex(int(flipped, 2))
        hex2 = hex(int(flipped2, 2))

        # add some padding to the hex numbers
        if len(hex1) == 3:
            vendor1 = "0" + hex1[2:] + row['VendorMAC'][2:]
        else:
            vendor1 = hex1[2:] + row['VendorMAC'][2:]
        if len(hex2) == 3:
            vendor2 = "0" + hex2[2:] + row['VendorMAC'][2:]
        else:
            vendor2 = hex2[2:] + row['VendorMAC'][2:]

        # find similar networks in the dataset with already identified vendors
        similar = ven.loc[((((ven['Vendor'].str.contains(vendor1[:6])) | (ven['Vendor'].str.contains(vendor2[:6]))) & (ven['BSSID'].str.contains(row['BSSID'][7:-1]))) |
                           (vendor1[2:] == row['BSSID'][2:])) & (ven['BSSID'] != row['BSSID'])]

        dataframeRow = df.loc[df['BSSID'] == row['BSSID']].iloc[0]
        # try to find a vendorName in the similar routers
        for i, r in similar.iterrows():
            if vendorName == "local":
                if i[:8] in vendors['VendorMAC'].tolist():
                    # uncomment next block for working with time
                    """
                    time1 = row['Time']
                    time1 = datetime.strptime(time1,'%Y-%m-%d %H:%M:%S.%f' )
                    time2 = r['Time']
                    time2 = datetime.strptime(time2,'%Y-%m-%d %H:%M:%S.%f' )
                    tdelta = time1 - time2
                    tdelta = tdelta.total_seconds()
                    if abs(tdelta) < 60:
                        vendorName = vendors.loc[vendors['VendorMAC'] == i[:8]].iloc[0]['VendorName']
                    else:
                        ssid1 = df.loc[df['BSSID'] == row['BSSID']].iloc[0]['SSID']
                        
                        ssid2 = df.loc[df['BSSID'] == r['BSSID']].iloc[0]['SSID']
                        out.write('The routers are to far from each other, they are probably not the same' + '\n')
                        out.write("distance: " + str(tdelta) + '\n')
                        out.write('similar MAC: ' + str(r['BSSID']) + ' - ' + str(time2) + '\n')
                        out.write('search MAC: ' + str(row['BSSID']) + ' - ' + str(time1) + '\n')
                        out.write(str(ssid2) + '\n')
                        out.write(str(ssid1) + '\n' + '\n')
                    """
                    # comment next block when working with time
                    # TODO adjust based on length that is necessary
                    index1 = np.where(df['BSSID'] == row['BSSID'])[0][0]
                    index2 = np.where(df['BSSID'] == r['BSSID'])[0][0]
                    if abs(int(index1)-int(index2) < 50 ):
                        vendorName = vendors.loc[vendors['VendorMAC'] == i[:8]].iloc[0]['VendorName']
                    else:
                        ssid1 = df.loc[df['BSSID'] == row['BSSID']].iloc[0]['SSID']
                        ssid2 = df.loc[df['BSSID'] == r['BSSID']].iloc[0]['SSID']
                        out.write('The routers are to far from each other, they are probably not the same' + '\n')
                        out.write("distance: " + str(abs(index1-index2)) + '\n')
                        out.write('similar MAC: ' + str(r['BSSID']) + '\n')
                        out.write('search MAC: ' + str(row['BSSID']) + '\n')
                        out.write(str(ssid2) + '\n')
                        out.write(str(ssid1) + '\n' + '\n')
                    #until here


    # update the local dataset
    local.at[row['BSSID'], "VendorName"] = vendorName

    # also add it to the vendors dataset
    vulnerable = 0
    dataframeRow = df.loc[df['BSSID'] == row['BSSID']].iloc[0]

    if (dataframeRow["eapol-amsdu"] == True) | (dataframeRow["eapol-forward"] == True) | (
            dataframeRow["plaintext-broadcast"] == True) | (
            dataframeRow["plaintext-fragmented-broadcast"] == True) | (
            dataframeRow["fragmentation-enterprise"] == True):
        vulnerable = 1
    assocDongle1en2 = 0
    if dataframeRow['AssociationDongle2'] == True and dataframeRow['AssociationDongle1'] == True:
        assocDongle1en2 = 1
    assocDongle1enDevice = 0
    if dataframeRow['AssociationDongle1'] == True and dataframeRow['connected-device'] == True:
        assocDongle1enDevice = 1

    eapolAmsduVW = 0
    if dataframeRow['eapol-amsdu'] == True and dataframeRow['AssociationDongle1'] == True:
        eapolAmsduVW = 1
    eapolForwardVW = 0
    if dataframeRow['eapol-forward'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow[
        'AssociationDongle2'] == True:
        eapolForwardVW = 1
    plaintextBroadcastVW = 0
    if dataframeRow['plaintext-broadcast'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow[
        'connected-device'] == True:
        plaintextBroadcastVW = 1
    plaintextFragmentedBroadcastVW = 0
    if dataframeRow['plaintext-fragmented-broadcast'] == True and dataframeRow['AssociationDongle1'] == True and \
            dataframeRow['connected-device'] == True:
        plaintextFragmentedBroadcastVW = 1

    # added for ping
    """
    plaintextPingVW = 0
    if dataframeRow['plaintext-ping'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow[
        'connected-device'] == True:
        plaintextPingVW = 1
    plaintextFragmentedPingVW = 0
    if dataframeRow['plaintext-fragmented-ping'] == True and dataframeRow['AssociationDongle1'] == True and \
            dataframeRow['connected-device'] == True:
        plaintextFragmentedPingVW = 1
    """
    fragmentationEnterpriseVW = 0
    if dataframeRow['fragmentation-enterprise'] == True and dataframeRow['AssociationDongle1'] == True and dataframeRow[
        'Enterprise'] == True:
        fragmentationEnterpriseVW = 1
    enterpriseAndAssociationDongle1 = 0
    if dataframeRow['AssociationDongle1'] == True and dataframeRow['Enterprise'] == True:
        enterpriseAndAssociationDongle1 = 1

    # add row to dataframe
    vendors.loc[row['BSSID']] = (row['BSSID'], dataframeRow['SSID'],
                                     row['VendorMAC'], vendorName, vulnerable, 1,dataframeRow['ouiList'],  1 if dataframeRow['WPS'] else 0,
                                     1 if dataframeRow['MFPcapable']=="1" else 0, 1 if dataframeRow['MFPrequired'] =="1" else 0,
                                     1 if dataframeRow['AssociationDongle1'] else 0,
                                     1 if dataframeRow['eapol-amsdu'] else 0, eapolAmsduVW, assocDongle1en2,
                                     1 if dataframeRow['eapol-forward'] else 0, eapolForwardVW, assocDongle1enDevice,
                                     1 if dataframeRow['plaintext-broadcast'] else 0, plaintextBroadcastVW,
                                     1 if dataframeRow['plaintext-fragmented-broadcast'] else 0, plaintextFragmentedBroadcastVW,
                                     #1 if dataframeRow['plaintext-ping'] else 0, plaintextPingVW,
                                     #1 if dataframeRow['plaintext-fragmented-ping'] else 0, plaintextFragmentedPingVW,
                                     1 if dataframeRow['Enterprise'] else 0, enterpriseAndAssociationDongle1,
                                     1 if dataframeRow['fragmentation-enterprise'] else 0, fragmentationEnterpriseVW)


vendorsTelenetWiFree = []
vendorsProximusPublic = []
vendorsOrangeGuest = []
vendorsTelenet = []
vendorsProximus = []
vendorsOrange = []
for index, row in vendors.iterrows():
    ssid = df.loc[df['BSSID'] == row['BSSID']].iloc[0]['SSID']
    if 'TelenetWiFree' in str(ssid):
        vendorsTelenetWiFree.append(row['VendorName'])
    if 'Guest-Orange' in str(ssid):
        vendorsOrangeGuest.append(row['VendorName'])
    if 'Proximus Public Wi-Fi' in str(ssid):
        vendorsProximusPublic.append(row['VendorName'])
    if 'telenet' in str(ssid).lower():
        vendorsTelenet.append(row['VendorName'])
    if 'proximus' in str(ssid).lower():
        vendorsProximusCertain.append(row['VendorName'])
    if 'orange' in str(ssid).lower():
        vendorsOrange.append(row['VendorName'])
vendorsTelenetWiFree = list(dict.fromkeys(vendorsTelenetWiFree))
vendorsProximusPublic = list(dict.fromkeys(vendorsProximusPublic))
vendorsOrangeGuest = list(dict.fromkeys(vendorsOrangeGuest))
vendorsTelenet = list(dict.fromkeys(vendorsTelenet))
vendorsProximus = list(dict.fromkeys(vendorsProximus))
vendorsOrange = list(dict.fromkeys(vendorsOrange))


# analyse TELENET certain networks

numberOfTelenetCertain = len(telenetCertain.index)
numberOfTelenetWiFreeCertain = len(telenetCertain.loc[telenetCertain['SSID'].str.contains("TelenetWiFree")])

telenetWiFreeCertain = telenetCertain.loc[(telenetCertain['SSID'].str.contains('TelenetWiFree', case=False, na=False))]
telenetWiFreeCertain = telenetWiFreeCertain.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
telenetWiFreeCertain = telenetWiFreeCertain.groupby("VendorName").sum().reset_index()
telenetWiFreeCertain = telenetWiFreeCertain.sort_values(by=['NumberOfDevices'], ascending=False)
telenetWiFreeCertain.to_csv('./'+ folder + '/Telenet/telenetWiFreeCertain.csv', escapechar='\\')

telenetWiFreeCertain['VendorName'] = 'TelenetWiFree'
telenetWiFreeCertain = telenetWiFreeCertain.groupby("VendorName").sum().reset_index()
telenetWiFreeCertain = telenetWiFreeCertain.sort_values(by=['NumberOfDevices'], ascending=False)
telenetWiFreeCertain.to_csv('./'+ folder + '/Telenet/telenetCertainWiFreeTotal.csv', escapechar='\\')

telenetCertainData = telenetCertain.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
telenetCertain = telenetCertainData.groupby("VendorName").sum().reset_index()
telenetCertain = telenetCertain.sort_values(by=['NumberOfDevices'], ascending=False)
telenetCertain.to_csv('./'+ folder + '/Telenet/telenetCertain.csv', escapechar='\\')

telenetCertain['VendorName'] = 'Telenet'
telenetCertain = telenetCertain.groupby("VendorName").sum().reset_index()
telenetCertain = telenetCertain.sort_values(by=['NumberOfDevices'], ascending=False)
telenetCertain.to_csv('./'+ folder + '/Telenet/telenetCertainTotal.csv', escapechar='\\')

# all telenet
telenetWiFree = vendors.loc[(vendors['SSID'].str.contains('TelenetWiFree', case=False, na=False))]
telenetWiFree = telenetWiFree.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
telenetWiFree = telenetWiFree.groupby("VendorName").sum().reset_index()
telenetWiFree = telenetWiFree.sort_values(by=['NumberOfDevices'], ascending=False)
telenetWiFree.to_csv('./'+ folder + '/Telenet/telenetWiFree.csv', escapechar='\\')

telenetWiFree['VendorName'] = 'TelenetWiFree'
telenetWiFree = telenetWiFree.groupby("VendorName").sum().reset_index()
telenetWiFree = telenetWiFree.sort_values(by=['NumberOfDevices'], ascending=False)
telenetWiFree.to_csv('./'+ folder + '/Telenet/telenetWiFreeTotal.csv', escapechar='\\')

telenet = vendors.loc[(vendors['SSID'].str.contains('telenet', case=False, na=False))]
numberOfTelenet = len(telenet.index)
numberOfTelenetWiFree = len(telenet.loc[telenet['SSID'].str.contains("TelenetWiFree")])

telenet = telenet.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
telenet = telenet.groupby("VendorName").sum().reset_index()
telenet = telenet.sort_values(by=['NumberOfDevices'], ascending=False)
telenet.to_csv('./'+ folder + '/Telenet/telenet.csv', escapechar='\\')

telenet['VendorName'] = 'Telenet'
telenet = telenet.groupby("VendorName").sum().reset_index()
telenet = telenet.sort_values(by=['NumberOfDevices'], ascending=False)
telenet.to_csv('./'+ folder + '/Telenet/telenetTotal.csv', escapechar='\\')


telenet = open('./'+ folder + '/Telenet/telenet.txt', 'w')

telenet.write('Analyse telenet certain networks:' + '\n')
telenet.write('Totaal aantal telenet certain networks: ' + str(numberOfTelenetCertain) + '\n')
telenet.write('Aantal TelenetWiFree certain networks: ' + str(numberOfTelenetWiFreeCertain) + '\n\n' )
telenet.write('Fabrikanten telenet certain: ' + str(vendorsTelenetCertain) + '\n\n')
telenet.write('Fabrikanten TelenetWiFree certain: ' + str(vendorsTelenetWiFreeCertain) + '\n\n')


telenet.write('Analyse all telenet networks:' + '\n')
telenet.write('Totaal aantal telenet networks: ' + str(numberOfTelenet) + '\n')
telenet.write('Aantal TelenetWiFree networks: ' + str(numberOfTelenetWiFree) + '\n\n' )
telenet.write('Fabrikanten telenet: ' + str(vendorsTelenet) + '\n\n')
telenet.write('Fabrikanten TelenetWiFree: ' + str(vendorsTelenetWiFree) + '\n\n')

telenet.close()

# analyse PROXIMUS certain networks

numberOfProximusCertain = len(proximusCertain.index)
numberOfProximusPublicCertain = len(proximusCertain.loc[proximusCertain['SSID'].str.contains("Proximus Public Wi-Fi")])

proximusCertain = proximusCertain.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
proximusCertain = proximusCertain.groupby("VendorName").sum().reset_index()
proximusCertain = proximusCertain.sort_values(by=['NumberOfDevices'], ascending=False)
proximusCertain.to_csv('./'+ folder + '/Proximus/proximusCertain.csv', escapechar='\\')

proximusCertain['VendorName'] = 'Proximus'
proximusCertain = proximusCertain.groupby("VendorName").sum().reset_index()
proximusCertain = proximusCertain.sort_values(by=['NumberOfDevices'], ascending=False)
proximusCertain.to_csv('./'+ folder + '/Proximus/proximusCertainTotal.csv', escapechar='\\')

# all proximus
proximusPublic = vendors.loc[(vendors['SSID'].str.contains('Proximus Public Wi-Fi', case=False, na=False))]
proximusPublic = proximusPublic.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
proximusPublic = proximusPublic.groupby("VendorName").sum().reset_index()
proximusPublic = proximusPublic.sort_values(by=['NumberOfDevices'], ascending=False)
proximusPublic.to_csv('./'+ folder + '/Proximus/proximusPublic.csv', escapechar='\\')

proximusPublic['VendorName'] = 'ProximusPublic'
proximusPublic = proximusPublic.groupby("VendorName").sum().reset_index()
proximusPublic = proximusPublic.sort_values(by=['NumberOfDevices'], ascending=False)
proximusPublic.to_csv('./'+ folder + '/Proximus/proximusPublicTotal.csv', escapechar='\\')

proximus = vendors.loc[(vendors['SSID'].str.contains('proximus', case=False, na=False))]
numberOfProximus = len(proximus.index)
numberOfProximusPublic = len(proximus.loc[proximus['SSID'].str.contains("Proximus Public Wi-Fi")])

proximus = proximus.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
proximus = proximus.groupby("VendorName").sum().reset_index()
proximus = proximus.sort_values(by=['NumberOfDevices'], ascending=False)
proximus.to_csv('./'+ folder + '/Proximus/proximus.csv', escapechar='\\')

proximus['VendorName'] = 'Proximus'
proximus = proximus.groupby("VendorName").sum().reset_index()
proximus = proximus.sort_values(by=['NumberOfDevices'], ascending=False)
proximus.to_csv('./'+ folder + '/Proximus/proximusTotal.csv', escapechar='\\')


proximus = open('./'+ folder + '/Proximus/proximus.txt', 'w')

proximus.write('Analyse proximus certain networks:' + '\n')
proximus.write('Totaal aantal proximus certain networks: ' + str(numberOfProximusCertain) + '\n')
proximus.write('Aantal proximusPublic certain networks: ' + str(numberOfProximusPublicCertain) + '\n\n' )
proximus.write('Fabrikanten proximus certain: ' + str(vendorsProximusCertain) + '\n\n')
proximus.write('Fabrikanten proximusPublic certain: ' + str(vendorsProximusPublicCertain) + '\n\n')


proximus.write('Analyse all proximus networks:' + '\n')
proximus.write('Totaal aantal proximus  networks: ' + str(numberOfProximus) + '\n')
proximus.write('Aantal proximusPublic  networks: ' + str(numberOfProximusPublic) + '\n\n' )
proximus.write('Fabrikanten proximus : ' + str(vendorsProximus) + '\n\n')
proximus.write('Fabrikanten proximusPublic : ' + str(vendorsProximusPublic) + '\n\n')

proximus.close()



# analyse Orange certain networks

numberOfOrangeCertain = len(orangeCertain.index)
numberOfOrangeGuestCertain = len(orangeCertain.loc[orangeCertain['SSID'].str.contains("Guest-Orange")])

orangeCertain = orangeCertain.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
orangeCertain = orangeCertain.groupby("VendorName").sum().reset_index()
orangeCertain = orangeCertain.sort_values(by=['NumberOfDevices'], ascending=False)
orangeCertain.to_csv('./'+ folder + '/Orange/orangeCertain.csv', escapechar='\\')

orangeCertain['VendorName'] = 'Orange'
orangeCertain = orangeCertain.groupby("VendorName").sum().reset_index()
orangeCertain = orangeCertain.sort_values(by=['NumberOfDevices'], ascending=False)
orangeCertain.to_csv('./'+ folder + '/Orange/orangeCertainTotal.csv', escapechar='\\')

# all proximus
orangeGuest = vendors.loc[(vendors['SSID'].str.contains('Guest-Orange', case=False, na=False))]
orangeGuest = orangeGuest.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
orangeGuest = orangeGuest.groupby("VendorName").sum().reset_index()
orangeGuest = orangeGuest.sort_values(by=['NumberOfDevices'], ascending=False)
orangeGuest.to_csv('./'+ folder + '/Orange/orangeGuest.csv', escapechar='\\')

orangeGuest['VendorName'] = 'Guest-Orange'
orangeGuest = orangeGuest.groupby("VendorName").sum().reset_index()
orangeGuest = orangeGuest.sort_values(by=['NumberOfDevices'], ascending=False)
orangeGuest.to_csv('./'+ folder + '/Orange/orangeGuestTotal.csv', escapechar='\\')

orange = vendors.loc[(vendors['SSID'].str.contains('orange', case=False, na=False))]
numberOfOrange = len(orange.index)
numberOfOrangeGuest = len(orange.loc[orange['SSID'].str.contains("Guest-Orange")])

orange = orange.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
orange = orange.groupby("VendorName").sum().reset_index()
orange = orange.sort_values(by=['NumberOfDevices'], ascending=False)
orange.to_csv('./'+ folder + '/Orange/orange.csv', escapechar='\\')

orange['VendorName'] = 'Orange'
orange = orange.groupby("VendorName").sum().reset_index()
orange = orange.sort_values(by=['NumberOfDevices'], ascending=False)
orange.to_csv('./'+ folder + '/Orange/orangeTotal.csv', escapechar='\\')


orange = open('./'+ folder + '/Orange/orange.txt', 'w')

orange.write('Analyse orange certain networks:' + '\n')
orange.write('Totaal aantal orange certain networks: ' + str(numberOfOrangeCertain) + '\n')
orange.write('Aantal orangeGuest certain networks: ' + str(numberOfOrangeGuestCertain) + '\n\n' )
orange.write('Fabrikanten orange certain: ' + str(vendorsOrangeCertain) + '\n\n')
orange.write('Fabrikanten orangeGuest certain: ' + str(vendorsOrangeGuestCertain) + '\n\n')


orange.write('Analyse all orange networks:' + '\n')
orange.write('Totaal aantal orange  networks: ' + str(numberOfOrange) + '\n')
orange.write('Aantal orangeGuest  networks: ' + str(numberOfOrangeGuest) + '\n\n' )
orange.write('Fabrikanten orange : ' + str(vendorsOrange) + '\n\n')
orange.write('Fabrikanten orangeGuest : ' + str(vendorsOrangeGuest) + '\n\n')

orange.close()



local = local.dropna()
local.to_csv('./'+ folder + '/local.csv', escapechar='\\')

localPure = local.loc[local['VendorName'] == 'local']
localPure.to_csv('./' + folder + '/localPure.csv', escapechar='\\')

numberOfLocalNetworks = len(local.index)
numberOfPureLocalNetworks = len(localPure.index)
out.write('Number of local networks: ' + str(numberOfLocalNetworks) + '\n')
out.write('Number of pure local networks: ' + str(numberOfPureLocalNetworks) + '\n\n')

TelenetWiFree = len(localPure.loc[localPure['SSID'].str.contains("TelenetWiFree")])
ProximusPublic = len(localPure.loc[localPure['SSID'].str.contains("Proximus Public Wi-Fi")])
out.write('Local pure TelenetWiFree networks: ' + str(TelenetWiFree) + '\n')
out.write('Local pure Proximus Public Wi-Fi networks: ' + str(ProximusPublic) + '\n\n')

vendorsTelenet = []
vendorsProximus = []
for index, row in vendors.iterrows():
    ssid = df.loc[df['BSSID'] == row['BSSID']].iloc[0]['SSID']
    if 'telenet' in str(ssid).lower():
        vendorsTelenet.append(row['VendorName'])
    if 'proximus' in str(ssid).lower():
        vendorsProximus.append(row['VendorName'])
vendorsTelenet = list(dict.fromkeys(vendorsTelenet))
vendorsProximus = list(dict.fromkeys(vendorsProximus))


telenet = vendors.loc[(vendors['SSID'].str.contains('telenet', case=False, na=False)) ]
telenet = telenet.set_index(["VendorMAC", "BSSID", "SSID", 'ouiList'])
telenet = telenet.groupby("VendorName").sum().reset_index()
telenet = telenet.sort_values(by=['NumberOfDevices'], ascending=False)
telenet.to_csv('./'+ folder + '/Telenet/telenet.csv', escapechar='\\')

"""
#duplicate
proximusCertain = proximusCertain.set_index(["VendorMAC", "BSSID", "SSID"])
proximusCertain = proximusCertain.groupby("VendorName").sum().reset_index()
proximusCertain = proximusCertain.sort_values(by=['NumberOfDevices'], ascending=False)
proximusCertain.to_csv('./'+ folder + '/proximusCertain.csv', escapechar='\\')
"""

out.write('Vendors of Telenet Wi-Free Certain: ' + str(vendorsTelenetWiFreeCertain) + '\n')
out.write('Vendors of Proximus Public Wi-Fi Certain: ' + str(vendorsProximusPublicCertain) + '\n')
out.write('Vendors of telenet: ' + str(vendorsTelenetCertain) + '\n')
out.write('Vendors of proximus Certain: ' + str(vendorsProximusCertain) + '\n')
out.write('Vendors of Telenet Wi-Free: ' + str(vendorsTelenet) + '\n')
out.write('Vendors of Proximus: ' + str(vendorsProximus) + '\n\n')


def percent(row):
    return row['Vulnerable'] / row['NumberOfDevices'] * 100

vendors.to_csv('./'+ folder + '/vendors.csv', escapechar='\\')

grouped = vendors.set_index(["VendorMAC", 'ouiList', "BSSID", "SSID"])
grouped = grouped.groupby("VendorName").sum().reset_index()
grouped = grouped.sort_values(by=['NumberOfDevices'], ascending=False)
grouped.insert(7, 'percent', grouped.apply(lambda row: percent(row), axis=1))


grouped.to_csv('./'+ folder + '/vendorsGrouped.csv', escapechar='\\')

localGrouped = local.set_index(["VendorMAC", "BSSID", "SSID"])
localGrouped = localGrouped.groupby("VendorName").sum().reset_index()
localGrouped = localGrouped.sort_values(by=['NumberOfDevices'], ascending=False)
localGrouped.to_csv('./'+ folder + '/vendorsLocalGrouped.csv', escapechar='\\')


# list of vendor specific oui numbers
dfGrouped = vendors[['BSSID', 'VendorName', 'ouiList']]
dfGrouped = dfGrouped.set_index(["BSSID"])
dfGrouped = dfGrouped.groupby("VendorName")
dfGrouped = dfGrouped.sum().reset_index()

dfGrouped.to_csv('./'+ folder + '/beaconsOuiGrouped.csv', escapechar='\\')

for index, row in dfGrouped.iterrows():
    ouiListString = row["ouiList"]
    ouiListString = ouiListString.replace("][", ", ")
    ouiList = ouiListString.split(", ")
    ouiListInt = []
    for el in ouiList:
        el = el.replace("[", "")
        el = el.replace("]", "")
        if el != "":
            ouiListInt.append(int(el))

    dfGrouped.at[index, "ouiList"] = ouiListInt

df1 = dfGrouped.copy()
for index1, row1 in dfGrouped.iterrows():
    ouiList1 = row1["ouiList"]
    for index2, row2 in dfGrouped.iterrows():
        if index1 != index2:
            newList = [x for x in ouiList1 if x not in row2["ouiList"]]
            ouiList1 = newList

    df1.at[index1, "ouiList"] = ouiList1

df1.to_csv('./'+ folder + '/beaconsUnique.csv', escapechar='\\')

out.close()