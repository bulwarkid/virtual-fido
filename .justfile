# Justfile for Virtual Fido E2E Testing
set shell := ["bash", "-c"]

# Variables
VM_USER := "amo"
VM_HOST := "192.168.64.6"
VM_PROJECT := "~/virtual-fido"

# Sync files to VM
sync:
    ssh {{VM_USER}}@{{VM_HOST}} "mkdir -p {{VM_PROJECT}}"
    rsync -avz --delete \
        --exclude='.git' \
        --exclude='transport/dkit/USBDriver/build' \
        --exclude='transport/dkit/USBDriver/BuildProduct' \
        --exclude='transport/dkit/USBDriver/DerivedData' \
        --exclude='transport/dkit/USBDriver/build-installer' \
        --exclude='transport/dkit/USBDriver/build-lib' \
        . {{VM_USER}}@{{VM_HOST}}:{{VM_PROJECT}}/
# Pull videos/screenshots from VM
pull_videos:
    rsync -avz {{VM_USER}}@{{VM_HOST}}:{{VM_PROJECT}}/videos/ videos/

# --- DKIT FLOW (DriverKit) ---

dkit_build:
    go clean -cache
    go build -o virtual-fido-dkit ./cmd/virtual-fido
    codesign --force --sign - --team-id YWN2K8NKBD -i id.bulwark.virtual-fido --entitlements transport/dkit/entitlements.plist virtual-fido-dkit

dkit_test: dkit_build sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_test"

dkit_auto: sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_auto"

dkit_insert args="": sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_insert \"{{args}}\""

dkit_activate:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_activate"

dkit_logs:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_logs"

# --- VHID FLOW (Virtual HID) ---

vhid_build: vhid_build_lib
    go clean -cache
    go build -tags hidvirtual -o virtual-fido-vhid ./cmd/virtual-fido
    otool -l virtual-fido-vhid | grep -q "@executable_path/transport/vhid/output/" || install_name_tool -add_rpath @executable_path/transport/vhid/output/ virtual-fido-vhid
    codesign --force --sign - --entitlements transport/vhid/entitlements.plist virtual-fido-vhid

vhid_build_lib:
    bash transport/vhid/HIDVirtualDevice/build.sh

vhid_test: vhid_build sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_test"

vhid_auto: sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_auto"

vhid_insert args="": sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_insert \"{{args}}\""

vhid_activate:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_activate"

vhid_logs:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_logs"

vhid_suite args="": vhid_build sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_suite \"{{args}}\""

# Generic commands
build: dkit_build vhid_build
remove: dkit_remove vhid_remove
dkit_remove:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile dkit_remove"
vhid_remove:
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile vhid_remove"

# --- Driver Management ---
reinstall-dkit: sync
    ssh {{VM_USER}}@{{VM_HOST}} "export PATH=/opt/homebrew/bin:\$PATH; cd {{VM_PROJECT}} && just -f vm.justfile reinstall"

# Default
default: build
