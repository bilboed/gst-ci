#!/bin/bash -eu

# build-local-fuzz.sh
#
# Build fuzzers with local fuzz runner and dynamic linking
#
# $SRC: location of code checkouts
# $OUT: location to put fuzzing targets and corpus
# $WORK: writable directory where all compilation should be executed


# 2) Build the target fuzzers

# All targets will be linked in with $LIB_FUZZING_ENGINE which contains the
# actual fuzzing runner. Anything fuzzing engine can be used provided it calls
# the same function as libfuzzer.

# Note: The fuzzer .o needs to be first compiled with CC and then linked with CXX

# These are the basic .pc dependencies required to build any of the fuzzing targets
# That is : glib, gstreamer core and gst-app
# The extra target-specific dependencies are to be specified later
COMMON_DEPS="glib-2.0 gstreamer-1.0 gstreamer-app-1.0"

# For each target, defined the following:
# TARGET_DEPS : Extra .pc dependencies for the target (in addition to $COMMON_DEPS)
#               All dependencies (including sub-dependencies) must be speecified
# PLUGINS : .a of the plugins to link
#           They must match the static plugins declared/registered in the target

#
# TARGET : push-based ogg/theora/vorbis discoverer
#
# FIXME : Rename to discoverer_push_oggtheoravorbis

TARGET_DEPS=" gstreamer-pbutils-1.0"

echo
echo ">>>> BUILDING gst-discoverer"
echo
BUILD_CFLAGS="$CFLAGS `pkg-config --cflags $COMMON_DEPS $TARGET_DEPS`"
BUILD_LDFLAGS="`pkg-config --libs $COMMON_DEPS $TARGET_DEPS`"

$CC $BUILD_CFLAGS $BUILD_LDFLAGS -DLOCAL_FUZZ_BUILD gst-discoverer.c localfuzzer.c -o gst-discoverer

echo
echo ">>>> BUILDING gst-discoverer_pull"
echo

$CC $BUILD_CFLAGS $BUILD_LDFLAGS -DLOCAL_FUZZ_BUILD -DPULL_MODE_FUZZER gst-discoverer.c localfuzzer.c -o gst-discoverer_pull

#
# TARGET : push-based typefind
#

# typefindfunction depends on pbutils which depends on gst{audio|video|tag}
TARGET_DEPS=""

echo
echo ">>>> BUILDING typefind"
echo
BUILD_CFLAGS="$CFLAGS `pkg-config --cflags $COMMON_DEPS $TARGET_DEPS`"
BUILD_LDFLAGS="`pkg-config --libs $COMMON_DEPS $TARGET_DEPS`"

$CC $BUILD_CFLAGS $BUILD_LDFLAGS -DLOCAL_FUZZ_BUILD typefind.c localfuzzer.c -o typefind

echo
echo ">>>> BUILDING typefind_pull"
echo

$CC $BUILD_CFLAGS $BUILD_LDFLAGS -DLOCAL_FUZZ_BUILD -DPULL_MODE_FUZZER typefind.c localfuzzer.c -o typefind_pull
