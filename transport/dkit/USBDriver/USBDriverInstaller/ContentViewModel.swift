//
//  ContentViewModel.swift
//  USBDriverInstaller
//
//  Created by Chris de la Iglesia on 12/31.22.
//

import Foundation
import SystemExtensions
import os.log

class ContentViewModel: NSObject, ObservableObject {
    var onCompletion: ((Bool) -> Void)?
    @Published var alertMessage: String?
    @Published var showAlert = false

    func activate() {
        print("LOG: Submit activation request")
        let request = OSSystemExtensionRequest
            .activationRequest(forExtensionWithIdentifier: "id.bulwark.VirtualUSBDriver.driver",
                               queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
    func deactivate() {
        print("LOG: Submit deactivation request")
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: "id.bulwark.VirtualUSBDriver.driver", queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

extension ContentViewModel: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        os_log("request actionForReplacingExtension");
        print("LOG: Request actionForReplacingExtension")
        // Always replace old version
        return .replace
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log("requestNeedsUserApproval")
        print("LOG: Request needs user approval")
        // If headless, we can't approve. But on SIP disabled, it might auto-approve?
        // We log it.
    }
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        os_log("didFinishWithResult: %d", result.rawValue);
        print("LOG: didFinishWithResult: \(result.rawValue)")
        let isActivation = request.identifier.contains("activation") // This is a bit hacky, but request doesn't easily expose if it's activate/deactivate
        // Better: check result or just a general success
        self.alertMessage = "Operation completed successfully."
        self.showAlert = true
        onCompletion?(true)
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        os_log("didFailWithError: %@", error.localizedDescription);
        print("LOG: didFailWithError: \(error.localizedDescription)")
        self.alertMessage = "Operation failed: \(error.localizedDescription)"
        self.showAlert = true
        onCompletion?(false)
    }
}
