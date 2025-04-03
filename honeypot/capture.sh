#!/bin/bash

sudo tcpdump -A -nn -l -v -i lo0 tcp dst port 9001 | while read -r line; do
    echo "[TCPDUMP] $line"

    IP=$(echo "$line" | awk '{split($3,a,"."); print a[1]"."a[2]"."a[3]"."a[4]}')
    PORT=$(echo "$line" | awk '{split($3,a,"."); print a[5]}')
    FULL_MSG=$(echo "$line")

    if [[ -n "$IP" && -n "$PORT" && -n "$FULL_MSG" ]]; then
        echo "Parsed IP=$IP PORT=$PORT FULL_MSG=$FULL_MSG"
        redis-cli HONEYPOT "$IP" "$PORT" "$FULL_MSG"
    fi
done
