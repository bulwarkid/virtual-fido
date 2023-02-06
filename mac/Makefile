all: lib

dext:
	xcodebuild -project USBDriver/USBDriver.xcodeproj -target USBDriver
	mv USBDriver/build/build/Release-driverkit/* ./output/

lib: clean
	xcodebuild -project USBDriver/USBDriver.xcodeproj -target USBDriverLib -configuration Release
	mkdir output
	mv USBDriver/build/build/Release/* ./output/

clean:
	-rm -r output