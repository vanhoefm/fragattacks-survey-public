#!/usr/bin/bash

sudo rfkill unblock wifi
sudo hostap-ent/hostapd/hostapd example_hostapd.conf
