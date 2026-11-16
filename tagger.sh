#!/bin/bash

# Configuration
QBIT_URL="http://gluetun:8080" # Adjust to your qBittorrent IP/Host and Port
QBIT_API_KEY="<KEY_HERE>" # Paste your generated qBittorrent API key here
# ---------------------

INDEXER="${sonarr_release_indexer:-$radarr_release_indexer}"
HASH="${sonarr_download_id:-$radarr_download_id}"

# Exit gracefully if missing required environment variables
if [ -z "$INDEXER" ] || [ -z "$HASH" ]; then
    exit 0
fi

# Clean up tag name (removes "(Prowlarr)" suffix if present)
TAG=$(echo "$INDEXER" | sed 's/ (Prowlarr)//g' | tr -d '\r\n')

# Brief pause for qBittorrent to receive the torrent
sleep 3

# Send tag command to qBittorrent Web API using API key authentication
curl -s -X POST "$QBIT_URL/api/v2/torrents/addTags" \
  -H "Authorization: Bearer $QBIT_API_KEY" \
  -d "hashes=$HASH&tags=$TAG" > /dev/null

