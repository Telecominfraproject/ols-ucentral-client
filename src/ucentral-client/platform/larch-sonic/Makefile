# This is a connector between ucentral-client Makefile and larch-sonic platform CMake.
# When `plat.a` target is requested, CMake generates the underlying build system files
# (i.e. Makefile) and make is run there.

CMAKE_BUILD_DIR := build

# <D - directory part (i.e. path without file) of the first prerequisite
# @D - directory part of the target
$(CMAKE_BUILD_DIR)/Makefile: CMakeLists.txt
	cmake -S $(<D) -B $(@D) -G "Unix Makefiles"

plat.a: $(CMAKE_BUILD_DIR)/Makefile
	$(MAKE) -C $(<D) $@
