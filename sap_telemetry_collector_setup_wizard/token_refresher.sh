#!/bin/sh
set -e

TOKEN_FILE="/etc/nginx/gcp_token.conf"

fetch_and_write_token() {
  TOKEN=$(wget -q -O - --timeout=3 --header="Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
  if [ -n "$TOKEN" ]; then
    echo "proxy_set_header Authorization \"Bearer $TOKEN\";" > "${TOKEN_FILE}.tmp"
    mv "${TOKEN_FILE}.tmp" "$TOKEN_FILE"
    return 0
  fi
  return 1
}

# 1. Initial token fetch before Nginx starts
if ! fetch_and_write_token; then
  echo "# No metadata token available at startup" > "$TOKEN_FILE"
fi

# 2. Background refresher process (every 1800s / 30m)
(
  while true; do
    sleep 1800
    if fetch_and_write_token; then
      nginx -s reload 2>/dev/null || true
    fi
  done
) &

exit 0
