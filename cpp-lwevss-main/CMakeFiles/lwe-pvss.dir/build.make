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
CMAKE_SOURCE_DIR = /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main

# Include any dependencies generated for this target.
include CMakeFiles/lwe-pvss.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/lwe-pvss.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/lwe-pvss.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lwe-pvss.dir/flags.make

CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o: src/25519/curve25519.cpp
CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/25519/curve25519.cpp

CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/25519/curve25519.cpp > CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.i

CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/25519/curve25519.cpp -o CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.s

CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o: src/algebra/foursquares.cpp
CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/foursquares.cpp

CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/foursquares.cpp > CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.i

CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/foursquares.cpp -o CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.s

CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o: src/algebra/ternaryMatrix.cpp
CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/ternaryMatrix.cpp

CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/ternaryMatrix.cpp > CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.i

CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/algebra/ternaryMatrix.cpp -o CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.s

CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o: src/dlproofs/bulletproof.cpp
CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/bulletproof.cpp

CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/bulletproof.cpp > CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.i

CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/bulletproof.cpp -o CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.s

CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o: src/dlproofs/constraints.cpp
CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/constraints.cpp

CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/constraints.cpp > CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.i

CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/constraints.cpp -o CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.s

CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o: src/dlproofs/naive.cpp
CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/naive.cpp

CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/naive.cpp > CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.i

CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/dlproofs/naive.cpp -o CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.s

CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o: src/libmerlin/merlin.c
CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o -MF CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o.d -o CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/libmerlin/merlin.c

CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/libmerlin/merlin.c > CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.i

CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/libmerlin/merlin.c -o CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.s

CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o: src/regev/regevEnc.cpp
CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevEnc.cpp

CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevEnc.cpp > CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.i

CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevEnc.cpp -o CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.s

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o: src/regev/regevProofs-utils.cpp
CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs-utils.cpp

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs-utils.cpp > CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.i

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs-utils.cpp -o CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.s

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o: src/regev/regevProofs.cpp
CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs.cpp

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs.cpp > CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.i

CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/regev/regevProofs.cpp -o CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.s

CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o: CMakeFiles/lwe-pvss.dir/flags.make
CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o: src/tools/shamir.cpp
CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o: CMakeFiles/lwe-pvss.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o -MF CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o.d -o CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o -c /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/tools/shamir.cpp

CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/tools/shamir.cpp > CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.i

CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/src/tools/shamir.cpp -o CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.s

# Object files for target lwe-pvss
lwe__pvss_OBJECTS = \
"CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o" \
"CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o" \
"CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o"

# External object files for target lwe-pvss
lwe__pvss_EXTERNAL_OBJECTS =

liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/25519/curve25519.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/algebra/foursquares.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/algebra/ternaryMatrix.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/dlproofs/bulletproof.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/dlproofs/constraints.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/dlproofs/naive.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/libmerlin/merlin.c.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/regev/regevEnc.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/regev/regevProofs-utils.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/regev/regevProofs.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/src/tools/shamir.cpp.o
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/build.make
liblwe-pvss.a: CMakeFiles/lwe-pvss.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Linking CXX static library liblwe-pvss.a"
	$(CMAKE_COMMAND) -P CMakeFiles/lwe-pvss.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lwe-pvss.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/lwe-pvss.dir/build: liblwe-pvss.a
.PHONY : CMakeFiles/lwe-pvss.dir/build

CMakeFiles/lwe-pvss.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lwe-pvss.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lwe-pvss.dir/clean

CMakeFiles/lwe-pvss.dir/depend:
	cd /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main /Users/jiahuiliu/Dropbox/PVSS/380D/cpp-lwevss-main/CMakeFiles/lwe-pvss.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/lwe-pvss.dir/depend

