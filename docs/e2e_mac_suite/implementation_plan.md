# Implementation Plan - Transport Spec Alignment

## Goal Description
Enhance `openspec` documentation to formally define the HID Report Descriptor and transport behaviors, aligning with FIDO CTAP 2.1 and WebAuthn standards. This addresses the gap where the "spec" is currently only implicit in the code.

## User Review Required
> [!NOTE]
> This plan focuses on documentation and specification alignment. No code changes are proposed for the transport implementation itself, as the review confirmed it is compliant.

## Proposed Changes

### Documentation (OpenSpec)

#### [NEW] `openspec/specs/transport/hid.md`
Create a new specification file that:
1.  Formalizes the FIDO HID Report Descriptor (Usage Page `0xF1D0`).
2.  Defines the required Report Size (64 bytes).
3.  Specifies the endpoints (Input `0x20`, Output `0x21`).
4.  Documents the behavioral requirement for rate limiting (Pacing) on macOS.

#### [MODIFY] `openspec/specs/architecture/spec.md`
Update the high-level architecture spec to reference the new detailed transport spec.

## Verification Plan

### Manual Verification
- Verify that the values in `openspec/specs/transport/hid.md` match the FIDO Registry of Predefined Values.
- Verify that the code in `report_descriptor.go` and `VirtualFIDODevice.swift` matches the new spec.
