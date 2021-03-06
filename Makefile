# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /works/projects/temp/asio-ssl-mutual-auth

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /works/projects/temp/asio-ssl-mutual-auth

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running interactive CMake command-line interface..."
	/usr/bin/cmake -i .
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /works/projects/temp/asio-ssl-mutual-auth/CMakeFiles /works/projects/temp/asio-ssl-mutual-auth/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /works/projects/temp/asio-ssl-mutual-auth/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named demo

# Build rule for target.
demo: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 demo
.PHONY : demo

# fast build rule for target.
demo/fast:
	$(MAKE) -f CMakeFiles/demo.dir/build.make CMakeFiles/demo.dir/build
.PHONY : demo/fast

#=============================================================================
# Target rules for targets named ssldemo

# Build rule for target.
ssldemo: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 ssldemo
.PHONY : ssldemo

# fast build rule for target.
ssldemo/fast:
	$(MAKE) -f CMakeFiles/ssldemo.dir/build.make CMakeFiles/ssldemo.dir/build
.PHONY : ssldemo/fast

client.o: client.cpp.o
.PHONY : client.o

# target to build an object file
client.cpp.o:
	$(MAKE) -f CMakeFiles/demo.dir/build.make CMakeFiles/demo.dir/client.cpp.o
.PHONY : client.cpp.o

client.i: client.cpp.i
.PHONY : client.i

# target to preprocess a source file
client.cpp.i:
	$(MAKE) -f CMakeFiles/demo.dir/build.make CMakeFiles/demo.dir/client.cpp.i
.PHONY : client.cpp.i

client.s: client.cpp.s
.PHONY : client.s

# target to generate assembly for a file
client.cpp.s:
	$(MAKE) -f CMakeFiles/demo.dir/build.make CMakeFiles/demo.dir/client.cpp.s
.PHONY : client.cpp.s

ssldemo.o: ssldemo.cpp.o
.PHONY : ssldemo.o

# target to build an object file
ssldemo.cpp.o:
	$(MAKE) -f CMakeFiles/ssldemo.dir/build.make CMakeFiles/ssldemo.dir/ssldemo.cpp.o
.PHONY : ssldemo.cpp.o

ssldemo.i: ssldemo.cpp.i
.PHONY : ssldemo.i

# target to preprocess a source file
ssldemo.cpp.i:
	$(MAKE) -f CMakeFiles/ssldemo.dir/build.make CMakeFiles/ssldemo.dir/ssldemo.cpp.i
.PHONY : ssldemo.cpp.i

ssldemo.s: ssldemo.cpp.s
.PHONY : ssldemo.s

# target to generate assembly for a file
ssldemo.cpp.s:
	$(MAKE) -f CMakeFiles/ssldemo.dir/build.make CMakeFiles/ssldemo.dir/ssldemo.cpp.s
.PHONY : ssldemo.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... demo"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... ssldemo"
	@echo "... client.o"
	@echo "... client.i"
	@echo "... client.s"
	@echo "... ssldemo.o"
	@echo "... ssldemo.i"
	@echo "... ssldemo.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

