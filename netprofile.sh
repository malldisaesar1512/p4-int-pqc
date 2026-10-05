#!/usr/bin/env bash
# Terapkan/bersihkan profil jaringan non-ideal di interface loopback (lo)
# milik h2. Dipakai di sini (bukan di link fisik Mininet) karena Sink Agent
# & Telemetry Collector sama-sama jalan di namespace h2, connect lewat
# 127.0.0.1 -- jadi "kanal ekspor" yg mau disimulasikan kondisinya itu
# trafik lewat lo.
#
# Pakai lewat:
#   sudo ~/mininet/util/m h2 bash netprofile.sh <ideal|moderate|severe|clear>

set -e
PROFILE="$1"

tc qdisc del dev lo root 2>/dev/null || true   # bersihin dulu, abaikan kalau belum ada

case "$PROFILE" in
  ideal)
    echo "[netprofile] ideal: tidak ada impairment"
    ;;
  moderate)
    tc qdisc add dev lo root netem delay 50ms loss 2%
    echo "[netprofile] moderate: delay 50ms, loss 2%"
    ;;
  severe)
    tc qdisc add dev lo root netem delay 200ms 20ms loss 10%
    echo "[netprofile] severe: delay 200ms (+-20ms jitter), loss 10%"
    ;;
  clear)
    echo "[netprofile] cleared"
    ;;
  *)
    echo "Unknown profile: $PROFILE (pilihan: ideal, moderate, severe, clear)"
    exit 1
    ;;
esac