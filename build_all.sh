#!/bin/bash
set -e

python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt

cd hostap-mesh-poc/research/
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r libwifi/requirements.txt
cd ../..

cd hostap-mesh-poc/wpa_supplicant/
cp defconfig .config
make -j 2
cd ../..

cd hostap-ent/hostapd/
cp defconfig .config
make -j 2
cd ../..

cd linux-driver-backports-6.1.110
make defconfig-hwsim
make -j 2

