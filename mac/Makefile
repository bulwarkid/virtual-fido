all: lib dext

dext:
	xcodebuild -project USBDriver/USBDriver.xcodeproj -target USBDriver
	mv USBDriver/build/build/Release-driverkit/* ./output/

lib: clean
	xcodebuild -project USBDriver/USBDriver.xcodeproj -target USBDriverLib
	mkdir output
	mv USBDriver/build/build/Release/* ./output/

tester:
	/usr/bin/codesign --force --sign - -o runtime --entitlements <> --timestamp\=none --generate-entitlement-der <>

clean:
	-rm -r output