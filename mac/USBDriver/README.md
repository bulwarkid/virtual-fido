# MacOS Virtual USB Device

This is a virtual USB device for MacOS implemented using DriverKit.

## Implementation Notes

-   Any binary that connects to the virtual USB driver needs to be signed using codesign and the entitlement `com.apple.developer.driverkit.userclient-access` with the value `id.bulwark.VirtualUSBDriver.driver`. (See USBDriverTester for an example.)
-   The driver requires signing from an Apple developer account, as well as the various driver protections turned off for development. For release, the driver would require an entitlement requested from Apple (See [this](https://developer.apple.com/documentation/driverkit/communicating_between_a_driverkit_extension_and_a_client_app?language=objc) and [this](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection?language=objc)).
-   The driver needs to be installed. Normally, the app that is distributed would install the driver, but here a sample app is provided in USBDriverInstaller. This installer also requires certain entitlements.
