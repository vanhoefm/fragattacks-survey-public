#!/usr/bin/bash
set -e

SPOOF_AMSDU=2
EAPOL_FORWARD=0
PLAINTEXT=0

# Enable all vulnerabilities by default, unless there was a request
# to only simulate a specific vulnerability
case "$1" in
	plain-full)
		echo "Simulating Plain. Full vulnerability (CVE-2020-26140)"
		PLAINTEXT=1
		;;
	plain-frag)
		echo "Simulating Plain. frag. vulnerability (CVE-2020-26143)"
		PLAINTEXT=2
		;;
	eapol-forward)
		echo "Simulating EAPOL Forward vulnerability (CVE-2020-26139)"
		EAPOL_FORWARD=1
		;;
	spoof-amsdu)
		echo "Simulating Spoof. A-MSDU vulnerability (CVE-2020-24588)"
		SPOOF_AMSDU=0
		;;
	fake-eapol)
		# Cannot directly simulate this. Instead, this can be 'simulated' by being
		# vulnerable to both Plain. Full and Spoof A-MSDU.
		echo "Simulating Fake EAPOL (CVE-2020-26144), Plain. Full (26140), and Spoof. A-MSDU (24588)"
		echo "Note that in our simulated setup, the Fake EAPOL vulnerability cannot be simulated on its own."
		SPOOF_AMSDU=0
		PLAINTEXT=1
		;;
	mesh-attack)
		SPOOF_AMSDU=1
		EAPOL_FORWARD=0
		PLAINTEXT=0
		;;
	mesh-defense)
		SPOOF_AMSDU=2
		EAPOL_FORWARD=0
		PLAINTEXT=0
		;;
	"")
		# Default is to simualte all vunerabilities
		echo "Simulating all vulnerabilities"
		SPOOF_AMSDU=0
		EAPOL_FORWARD=1
		PLAINTEXT=3
		;;
	*)
		echo "Valid arguments: plain-full, plain-frag, eapol-forward, spoof-amsdu, fake-eapol, mesh-attack, mesh-defense, <none>."
		exit 1
		;;
esac

sudo rmmod mac80211_hwsim mac80211 cfg80211 2> /dev/null || true
sudo modprobe cfg80211 amsdu_spoof_protection=$SPOOF_AMSDU
sudo modprobe mac80211 allow_eapol_forward=$EAPOL_FORWARD allow_plaintext=$PLAINTEXT
sudo modprobe mac80211_hwsim radios=4

sleep 0.5
sudo rfkill unblock wifi

echo "Done. ===> Restart all scripts if they were already running. <==="
