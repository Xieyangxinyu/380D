# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.20.5/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.20.5/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_shamir.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/test_shamir.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_shamir.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_shamir.dir/flags.make

tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o: tests/CMakeFiles/test_shamir.dir/flags.make
tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o: tests/test_shamir.cpp
tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o: tests/CMakeFiles/test_shamir.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o"
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o -MF CMakeFiles/test_shamir.dir/test_shamir.cpp.o.d -o CMakeFiles/test_shamir.dir/test_shamir.cpp.o -c /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests/test_shamir.cpp

tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_shamir.dir/test_shamir.cpp.i"
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests/test_shamir.cpp > CMakeFiles/test_shamir.dir/test_shamir.cpp.i

tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_shamir.dir/test_shamir.cpp.s"
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests/test_shamir.cpp -o CMakeFiles/test_shamir.dir/test_shamir.cpp.s

# Object files for target test_shamir
test_shamir_OBJECTS = \
"CMakeFiles/test_shamir.dir/test_shamir.cpp.o"

# External object files for target test_shamir
test_shamir_EXTERNAL_OBJECTS =

tests/test_shamir: tests/CMakeFiles/test_shamir.dir/test_shamir.cpp.o
tests/test_shamir: tests/CMakeFiles/test_shamir.dir/build.make
tests/test_shamir: liblwe-pvss.a
tests/test_shamir: /usr/local/Cellar/libsodium/1.0.18_1/lib/libsodium.dylib
tests/test_shamir: /usr/local/lib/libntl.dylib
tests/test_shamir: /usr/local/lib/libgmp.dylib
tests/test_shamir: tests/CMakeFiles/test_shamir.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_shamir"
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_shamir.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_shamir.dir/build: tests/test_shamir
.PHONY : tests/CMakeFiles/test_shamir.dir/build

tests/CMakeFiles/test_shamir.dir/clean:
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_shamir.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_shamir.dir/clean

tests/CMakeFiles/test_shamir.dir/depend:
	cd /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests /Users/jiahuiliu/Dropbox/UTcourses/Spring2022/distributed/project-related/cpp-lwevss-main-MODIFIED/tests/CMakeFiles/test_shamir.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_shamir.dir/depend

