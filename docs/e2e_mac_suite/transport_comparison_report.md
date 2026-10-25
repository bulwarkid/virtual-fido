# Transport Code Review: UHID vs. VHID & Standard Alignment

## 1. Executive Summary

This review compares the **Linux (UHID)** and **macOS (VHID)** transport implementations for the Virtual FIDO device. It evaluates their code structure, feature parity, and compliance with **FIDO CTAP HID** and **WebAuthn** standards.

**Key Findings:**
*   **Protocol Compliance**: Both implementations use an identical FIDO HID Report Descriptor that aligns with FIDO U2F/CTAP specs.
*   **Feature Parity**: Both support basic 64-byte report exchange. `vhid` adds sophisticated pacing and async handling for macOS stability. `uhid` relies on kernel buffering.
*   **Spec Gap**: The `openspec` documentation is too high-level ("Architecture" only) and lacks a rigorous DSL or schema for the HID descriptor, relying on code-defined byte arrays.

## 2. Implementation Comparison

| Feature | Linux (`uhid`) | macOS (`vhid`) |
| :--- | :--- | :--- |
| **Driver Interface** | `/dev/uhid` (Character Device) | `CoreHID` (User-mode Framework via Swift) |
| **Report Descriptor** | Hardcoded in `report_descriptor.go` | Hardcoded in `VirtualFIDODevice.swift` |
| **Descriptor Content** | **Identical** (Matches FIDO Standard) | **Identical** (Matches FIDO Standard) |
| **Input Reports** | Synchronous `Write` to file descriptor | Async `dispatchInputReport` with **Pacing** |
| **Report Size** | Strict check: `len(report) == 64` | Flexible: Pads/Truncates to 64 bytes |
| **Concurrency** | Single goroutine loop reading `/dev/uhid` | Swift `Task` based async/await + Dispatch Queue |
| **Error Handling** | Go standard `error` | Swift `do-catch` + `NSLog` |

### Code Analysis

**Linux (`uhid`):** `transport/uhid/device_linux.go`
*   **Pros**: Simple, idiomatic Go. Direct kernel interface. synchronous control flow is easy to reason about.
*   **Cons**: No built-in pacing (relies on kernel behaving). Strict report size check might be brittle if upper layers are sloppy.

**macOS (`vhid`):** `transport/vhid/vhid.go` + Swift
*   **Pros**: Robust handling of macOS strict timing requirements (20ms pacing prevents "Resource Busy" errors). Async architecture prevents blocking main thread.
*   **Cons**: Complex build chain (Cgo -> ObjC -> Swift). Logic split between Go and Swift.

## 3. Standard Validation (WebAuthn / FIDO CTAP)

The **WebAuthn** standard (W3C) defines the browser API (`navigator.credentials.create`). The underlying transport protocol is defined by **Client to Authenticator Protocol (CTAP)**.

**Validation against [FIDO Registry of Predefined Values](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html):**

*   **Usage Page**: `0xF1D0` (FIDO Alliance) - ✅ Correctly used in both.
*   **Usage**: `0x01` (U2F Authenticator) - ✅ Correctly used in both.
*   **Report Size**: 64 Bytes - ✅ Standard for U2F HID.
*   **Endpoints**:
    *   Input (Device -> Host): Usage `0x20` - ✅ Correct.
    *   Output (Host -> Device): Usage `0x21` - ✅ Correct.

**Conclusion**: The HID Report Descriptor used in both implementations is **fully compliant** with FIDO CTAP specifications for a U2F HID device.

## 4. Spec Alignment & Gaps

The current `openspec` definitions (`openspec/specs/architecture/spec.md`) are descriptions of *requirements*, not specifications of the *interface*.

**Identified Gaps:**
1.  **Missing "Source of Truth"**: The Report Descriptor is duplicated in Go and Swift code. There is no central spec/DSL file defining it.
2.  **No Formal DSL**: The "DSL" requested by the user does not exist. We rely on raw byte arrays.
3.  **Behavioral Spec**: The 20ms pacing on macOS is an implementation detail, not specified in `openspec`.

## 5. Enhancement Plan

To align with the request "enhance our specs to be aligned to requirements of standard":

1.  **Create `specs/transport/hid-descriptor.md`**: Define the HID Report Descriptor tables formally.
2.  **Defined Behavioral Requirements**: Add requirements for "Rate Limiting / Pacing" to the transport spec to formalize the macOS constraints.
3.  **Single Source of Truth**: Ideally, generate the byte arrays from the spec, but for now, add a "Compliance" section linking the code directly to the specific FIDO standard sections.
