# MacOS Virtual USB Device

This is a virtual USB device for MacOS implemented using DriverKit.

## How to Use

-   In order to create a virtual USB device with this library, the driver's dext must be installed.
    -   In order to create the dext, build the USBDriver target in this project.
    -   The dext must be stored inside an `.app` bundle, inside the `Contents/Library/SystemExtensions` folder.
    -   The app must be signed with the `com.apple.developer.system-extension.install` entitlement (see USBDriverInstaller).
    -   The app must then install the driver using `OSSystemExtensionManager`.
    -   In addition, SIP and other protections must be disabled on the development machine (see [this](https://developer.apple.com/documentation/driverkit/debugging_and_testing_system_extensions?language=objc)). For production use, the driver/app must be signed by a developer account that has been approved by Apple.
    -   See [this](https://developer.apple.com/documentation/kernel/implementing_drivers_system_extensions_and_kexts?language=objc) and [this](https://developer.apple.com/documentation/driverkit/creating_a_driver_using_the_driverkit_sdk?language=objc) for full documentation.
-   Once the driver has been installed on the local machine, your app (not necessarily the one that installed it) can connect to the driver to create a virtual USB device.
    -   This app needs the `com.apple.developer.driverkit.userclient-access` entitlement.
    -   This app can use the USBDriverLib library for easier use of connecting and using the driver.
