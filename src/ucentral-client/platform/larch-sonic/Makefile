# This is a connector between ucentral-client Makefile and larch-sonic platform CMake.
# When `plat.a` target is requested, CMake generates the underlying build system files
# (i.e. Makefile) and make is run there.

CMAKE_FILE := CMakeLists.txt
CMAKE_BUILD_DIR := build

MACHINE_ARCH := $(shell arch)
CMAKE_VERSION := 3.29.3
CMAKE_DIR := cmake-$(CMAKE_VERSION)-linux-$(MACHINE_ARCH)
CMAKE_BINARY := $(CMAKE_DIR)/bin/cmake

plat.a: $(CMAKE_BUILD_DIR)/Makefile
	$(MAKE) -C $(<D) $@

# <D - directory part (i.e. path without file) of the first prerequisite
# @D - directory part of the target
$(CMAKE_BUILD_DIR)/Makefile: $(CMAKE_BINARY) $(CMAKE_FILE)
	$(CMAKE_BINARY) -S $(dir $(CMAKE_FILE)) -B $(@D) -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug

$(CMAKE_BINARY):
	wget -qO- --no-check-certificate "https://github.com/Kitware/CMake/releases/download/v$(CMAKE_VERSION)/cmake-$(CMAKE_VERSION)-linux-$(MACHINE_ARCH).tar.gz" | tar -xz
