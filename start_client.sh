#!/usr/bin/bash

sudo rfkill unblock wifi
sudo wpa_supplicant -D nl80211 -i wlan3 -c client.conf
