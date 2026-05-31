ARCHS := arm64
TARGET := iphone:clang:latest:14.0

THEOS_LEAN_AND_MEAN = 1
FINALPACKAGE := 1
DEBUG = 0

ROOTLESS := 0

THEOS_PACKAGE_SCHEME =
ifeq ($(ROOTLESS),1)
THEOS_PACKAGE_SCHEME = rootless
endif

# CLI Tool
TOOL_NAME = decryptbinary
$(TOOL_NAME)_FILES = decryptBinary_src/main.m
$(TOOL_NAME)_CFLAGS = -w
$(TOOL_NAME)_FRAMEWORKS = MobileCoreServices
$(TOOL_NAME)_CODESIGN_FLAGS = -Sentitlements.plist
ifeq ($(ROOTLESS),1)
$(TOOL_NAME)_INSTALL_PATH = /usr/bin
$(TOOL_NAME)_CFLAGS += -DPLIST_PATH=\"/var/jb/Library/MobileSubstrate/DynamicLibraries/decryptBinaryDylib.plist\"
else
$(TOOL_NAME)_INSTALL_PATH = /usr/local/bin
$(TOOL_NAME)_CFLAGS += -DPLIST_PATH=\"/Library/MobileSubstrate/DynamicLibraries/decryptBinaryDylib.plist\"
endif

# Tweak/Dylib
TWEAK_NAME = decryptBinaryDylib
$(TWEAK_NAME)_FILES = decryptBinary_src/decryptBinary.xm
$(TWEAK_NAME)_CFLAGS = -w
$(TWEAK_NAME)_LIBRARIES = substrate
$(TWEAK_NAME)_FRAMEWORKS = MobileCoreServices
$(TWEAK_NAME)_INSTALL_PATH = /Library/MobileSubstrate/DynamicLibraries

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/tool.mk

after-install::
	install.exec "killall -9 SpringBoard"
