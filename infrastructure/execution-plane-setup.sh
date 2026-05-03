#!/bin/bash
apt-get update && apt-get install -y python3-pip mininet openvswitch-switch iptables mitmproxy
pip3 install scapy requests mitmproxy
export CONTROL_PLANE_URL="https://<ALB_DNS_NAME>"
export MACDS_API_KEY="$(aws secretsmanager get-secret-value \
    --secret-id macds/api-key --region ap-south-1 \
    --query SecretString --output text)"
sudo CONTROL_PLANE_URL="$CONTROL_PLANE_URL" MACDS_API_KEY="$MACDS_API_KEY" \
     python3 execution_plane/ids/deep_packet_inspector.py
