import Foundation
import CoreHID

/// FIDO U2F/CTAP HID Report Descriptor
/// Based on FIDO Alliance CTAP HID Protocol Specification
let FIDOReportDescriptor: [UInt8] = [
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,        // Usage (U2F Authenticator Device)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (Input Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8 bits)
    0x95, 0x40,        //   Report Count (64 bytes)
    0x81, 0x02,        //   Input (Data, Variable, Absolute)
    0x09, 0x21,        //   Usage (Output Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8 bits)
    0x95, 0x40,        //   Report Count (64 bytes)
    0x91, 0x02,        //   Output (Data, Variable, Absolute)
    0xC0               // End Collection
]

/// Callback type for receiving HID reports from the system
public typealias HIDReportCallback = @convention(c) (UnsafePointer<UInt8>, UInt) -> Void

/// Delegate for handling HID device events
final class VirtualFIDODeviceDelegate: HIDVirtualDeviceDelegate, @unchecked Sendable {
    private var callback: HIDReportCallback?
    
    func setCallback(_ callback: @escaping HIDReportCallback) {
        self.callback = callback
    }
    
    func hidVirtualDevice(_ device: HIDVirtualDevice, 
                         receivedGetReportRequestOfType type: HIDReportType, 
                         id: HIDReportID?, 
                         maxSize: Int) async throws -> Data {
        return Data()
    }
    
    func hidVirtualDevice(_ device: HIDVirtualDevice, 
                         receivedSetReportRequestOfType type: HIDReportType, 
                         id: HIDReportID?, 
                         data: Data) async throws {
        if type == .output, let callback = callback {
            let hex = data.prefix(8).map { String(format: "%02x", $0) }.joined()
            NSLog("[HIDVirtualDevice] RX Output Report: [%@]... (%d bytes)", hex, data.count)
            data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                if let baseAddress = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                    callback(baseAddress, UInt(data.count))
                }
            }
        }
    }
}

/// Swift wrapper for HIDVirtualDevice with async/await support
@objc public class VirtualFIDODevice: NSObject {
    private var device: HIDVirtualDevice?
    private var delegate: VirtualFIDODeviceDelegate
    private var activationTask: Task<Void, Never>?
    
    @objc public init(deviceName: String) {
        NSLog("[HIDVirtualDevice] init started for device: %@", deviceName)
        self.delegate = VirtualFIDODeviceDelegate()
        super.init()
        
        let properties = HIDVirtualDevice.Properties(
            descriptor: Data(FIDOReportDescriptor),
            vendorID: 0x1050,  // Yubico vendor ID
            productID: 0x0407,  // Yubikey 5 USB
            transport: .virtual,
            product: deviceName
        )
        
        NSLog("[HIDVirtualDevice] Creating HIDVirtualDevice instance...")
        device = HIDVirtualDevice(properties: properties)
    }
    
    @objc public func activate() {
        NSLog("[HIDVirtualDevice] activate() called")
        activationTask = Task {
            NSLog("[HIDVirtualDevice] Calling device.activate()...")
            await device?.activate(delegate: delegate)
            NSLog("[HIDVirtualDevice] Device activated successfully!")
        }
    }
    
    deinit {
        activationTask?.cancel()
    }
    
    /// Internal queue for paced report dispatch
    private var currentPacedTask: Task<Void, Never>?
    
    /// Send an input report to the system
    @objc public func sendReport(data: Data) {
        // Enforce 64-byte padding
        var reportData = data
        if reportData.count < 64 {
            reportData.append(Data(repeating: 0, count: 64 - reportData.count))
        } else if reportData.count > 64 {
            reportData = reportData.prefix(64)
        }

        // Chain tasks to ensure sequential pacing
        let previousTask = currentPacedTask
        currentPacedTask = Task {
            // Wait for previous burst to finish
            if let previous = previousTask {
                _ = await previous.result
            }
            
            do {
                if let device = self.device {
                    let hex = reportData.prefix(8).map { String(format: "%02x", $0) }.joined()
                    NSLog("[HIDVirtualDevice] TX Input Report: [%@]... (%d bytes)", hex, reportData.count)
                    
                    try await device.dispatchInputReport(data: reportData, timestamp: .now)
                    
                    // Pace at 20ms - very safe for VMs
                    try await Task.sleep(nanoseconds: 20_000_000)
                }
            } catch {
                NSLog("[HIDVirtualDevice] Failed to dispatch report: %@", error.localizedDescription)
            }
        }
    }
    
    /// Set callback for receiving output reports from the system
    @objc public func setCallback(_ callback: @escaping HIDReportCallback) {
        delegate.setCallback(callback)
    }
}
