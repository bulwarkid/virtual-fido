#!/bin/bash
# VM-side script to test sites with virtual-fido running (non-headless for debugging)
# Usage: ./test_online.sh [local|webauthn.io|yubico]

set -e

SITE=${1:-local}
PYTHON="/Users/amo/.pyenv/versions/3.12.12/bin/python3.12"
SERVER_PID=""

case "$SITE" in
    local)
        URL="http://localhost:8000"
        # Start local test server
        echo "Starting local test server..."
        $PYTHON test/server.py > /tmp/server.log 2>&1 &
        SERVER_PID=$!
        sleep 3
        ;;
    webauthn.io)
        URL="https://webauthn.io"
        ;;
    yubico)
        URL="https://demo.yubico.com/webauthn-technical/registration"
        ;;

    *)
        URL="$SITE"
        ;;
esac

echo "=========================================="
echo "Testing: $URL"
echo "=========================================="

# Start virtual-fido in background
echo "Starting virtual-fido..."
sudo pkill -9 -f "virtual-fido-vhid" || true
sleep 1

[ -f /tmp/seed_e2e ] || (head -c 32 /dev/urandom | xxd -p | tr -d '\n' > /tmp/seed_e2e)

sudo ./virtual-fido-vhid run \
    --device-name "HH-E2E" \
    --seed-file /tmp/seed_e2e \
    --always-approve \
    > /tmp/vhid.log 2>&1 &

VHID_PID=$!
echo "virtual-fido started (PID: $VHID_PID)"
sleep 5

# Run the test (non-headless for debugging)
echo "Running Playwright test (visible browser)..."
$PYTHON scripts/manual_test.py \
    --site "$URL" \
    --username "test_$(date +%s)"

TEST_RESULT=$?

# Cleanup
echo "Stopping virtual-fido..."
sudo kill $VHID_PID || true
sleep 1

if [ -n "$SERVER_PID" ]; then
    echo "Stopping local test server..."
    kill $SERVER_PID || true
fi

if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ Test PASSED"
else
    echo "❌ Test FAILED"
    echo "Check /tmp/vhid.log for virtual-fido logs"
    [ -n "$SERVER_PID" ] && echo "Check /tmp/server.log for server logs"
fi

exit $TEST_RESULT
