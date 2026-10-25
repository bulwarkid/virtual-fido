#!/bin/bash
set -e

echo "Building HIDVirtualDevice Swift library..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../output"
TEMP_DIR="$OUTPUT_DIR/temp"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$TEMP_DIR"

# Stage 1: Compile Swift code and generate header
echo "Stage 1: Compiling Swift..."
swiftc \
    -emit-library \
    -emit-module \
    -emit-objc-header \
    -emit-objc-header-path "$TEMP_DIR/VirtualFIDODevice-Swift.h" \
    -module-name VirtualFIDODevice \
    -Xlinker -install_name -Xlinker "@rpath/libVirtualFIDODevice_swift.dylib" \
    -o "$TEMP_DIR/libVirtualFIDODevice_swift.dylib" \
    -framework CoreHID \
    -framework Foundation \
    "$SCRIPT_DIR/VirtualFIDODevice.swift"

# Stage 2: Compile Objective-C bridge with generated Swift header
echo "Stage 2: Compiling Objective-C bridge..."
clang \
    -dynamiclib \
    -fobjc-arc \
    -framework Foundation \
    -framework CoreHID \
    -I"$TEMP_DIR" \
    -L"$TEMP_DIR" \
    -lVirtualFIDODevice_swift \
    -Xlinker -install_name -Xlinker "@rpath/libHIDVirtualDevice.dylib" \
    -Xlinker -rpath -Xlinker "@loader_path/." \
    -o "$OUTPUT_DIR/libHIDVirtualDevice.dylib" \
    "$SCRIPT_DIR/HIDVirtualDeviceBridge.m"

# Copy Swift dylib to output
cp "$TEMP_DIR/libVirtualFIDODevice_swift.dylib" "$OUTPUT_DIR/"

# Copy headers
mkdir -p "$OUTPUT_DIR/include/HIDVirtualDevice"
cp "$SCRIPT_DIR/HIDVirtualDeviceBridge.h" "$OUTPUT_DIR/include/HIDVirtualDevice/"

echo "✅ HIDVirtualDevice library built successfully"
echo "   Swift lib:  $OUTPUT_DIR/libVirtualFIDODevice_swift.dylib"
echo "   Bridge lib: $OUTPUT_DIR/libHIDVirtualDevice.dylib"
echo "   Header:     $OUTPUT_DIR/include/HIDVirtualDevice/HIDVirtualDeviceBridge.h"
