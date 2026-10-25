# Justfile for Guest VM (macOS)
set shell := ["bash", "-c"]

# Path validation
PROJECT_DIR := shell("pwd")
PYTHON := "/Users/amo/.pyenv/versions/3.12.12/bin/python3.12"

# install python dependencies
deps:
    {{PYTHON}} -m pip install playwright
    {{PYTHON}} -m playwright install chromium

# --- DKIT FLOW (DriverKit) ---

dkit_cleanup:
    echo "Cleaning up DKIT..."
    sudo pkill -9 -f "virtual-fido-dkit" || true

dkit_test: dkit_cleanup deps dkit_verify

dkit_verify:
    chmod +x {{PROJECT_DIR}}/virtual-fido-dkit
    echo "Running DKIT E2E Test..."
    cd {{PROJECT_DIR}} && {{PYTHON}} -u scripts/e2e_orch.py --binary ./virtual-fido-dkit --log /tmp/virtual-fido-dkit.log --signal /tmp/fido_approve_dkit

dkit_insert args="":
    @echo "Inserting Virtual FIDO Key (DKIT)..."
    sudo pkill -9 -f "virtual-fido-dkit" || true
    sudo rm -f /tmp/virtual-fido-dkit.log
    echo "--- DKIT LOG START: $(date) ---" | sudo tee /tmp/virtual-fido-dkit.log > /dev/null
    chmod +x {{PROJECT_DIR}}/virtual-fido-dkit
    [ -f /tmp/seed ] || (head -c 32 /dev/urandom | xxd -p | tr -d '\n' > /tmp/seed)
    cd {{PROJECT_DIR}} && sudo bash -c "nohup ./virtual-fido-dkit run --seed-file /tmp/seed --transport darwin --signal-file /tmp/fido_approve_dkit {{args}} >> /tmp/virtual-fido-dkit.log 2>&1 &"
    @echo "DKIT Key inserted. Logs at /tmp/virtual-fido-dkit.log"

dkit_auto:
    just -f vm.justfile dkit_insert "--always-approve --auto-select"

dkit_activate:
    sudo touch /tmp/fido_approve_dkit
    @echo "Sent DKIT activation signal."

dkit_remove:
    sudo pkill -9 -f "virtual-fido-dkit" || true

dkit_logs:
    tail -f /tmp/virtual-fido-dkit.log

# --- VHID FLOW (Virtual HID) ---

vhid_cleanup:
    echo "Cleaning up VHID..."
    sudo pkill -9 -f "virtual-fido-vhid" || true

vhid_test: vhid_cleanup deps vhid_verify

vhid_verify:
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    echo "Running VHID E2E Test..."
    cd {{PROJECT_DIR}} && {{PYTHON}} -u scripts/e2e_orch.py --binary ./virtual-fido-vhid --log /tmp/virtual-fido-vhid.log --signal /tmp/fido_approve_vhid

vhid_insert args="":
    @echo "Inserting Virtual FIDO Key (VHID)..."
    sudo pkill -9 -f "virtual-fido-vhid" || true
    sudo rm -f /tmp/virtual-fido-vhid.log
    echo "--- VHID LOG START: $(date) ---" | sudo tee /tmp/virtual-fido-vhid.log > /dev/null
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    [ -f /tmp/seed ] || (head -c 32 /dev/urandom | xxd -p | tr -d '\n' > /tmp/seed)
    cd {{PROJECT_DIR}} && sudo bash -c "nohup ./virtual-fido-vhid run --seed-file /tmp/seed --transport darwin --signal-file /tmp/fido_approve_vhid {{args}} >> /tmp/virtual-fido-vhid.log 2>&1 &"
    @echo "VHID Key inserted. Logs at /tmp/virtual-fido-vhid.log"

vhid_auto:
    just -f vm.justfile vhid_insert "--always-approve --auto-select"

vhid_activate:
    sudo touch /tmp/fido_approve_vhid
    @echo "Sent VHID activation signal."

vhid_remove:
    sudo pkill -9 -f "virtual-fido-vhid" || true

vhid_logs:
    tail -f /tmp/virtual-fido-vhid.log

vhid_suite args="": vhid_cleanup deps
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    echo "Running Full VHID E2E Suite..."
    cd {{PROJECT_DIR}} && {{PYTHON}} -u scripts/e2e_suite.py --binary ./virtual-fido-vhid {{args}}

# Manual E2E testing with visible browser (for debugging)
vhid_test_local_visible: vhid_cleanup deps
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    echo "Testing Local (Offline) with visible browser..."
    cd {{PROJECT_DIR}} && bash scripts/test_online.sh local

vhid_test_webauthn_visible: vhid_cleanup deps
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    echo "Testing WebAuthn.io with visible browser..."
    cd {{PROJECT_DIR}} && bash scripts/test_online.sh webauthn.io

vhid_test_yubico_visible: vhid_cleanup deps
    chmod +x {{PROJECT_DIR}}/virtual-fido-vhid
    echo "Testing Yubico with visible browser..."
    cd {{PROJECT_DIR}} && bash scripts/test_online.sh yubico

# Legacy/Default alias (default to dkit for now)
insert args="": (dkit_insert args)
remove: dkit_remove
auto: dkit_auto
cleanup: dkit_cleanup vhid_cleanup
