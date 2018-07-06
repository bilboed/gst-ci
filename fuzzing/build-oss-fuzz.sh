#!/bin/bash -eu

# build-oss-fuzz.sh
#
# Build script which is executed by oss-fuzz build.sh
#
# $SRC: location of code checkouts
# $OUT: location to put fuzzing targets and corpus
# $WORK: writable directory where all compilation should be executed
#
# /!\ Do not override any CC, CXX, CFLAGS, ... variables
#

# This script is divided in two parts
#
# 1) Build all the dependencies statically
#
# 2) Build the fuzzing targets

# Prefix where we will temporarily install everything
PREFIX=$WORK/prefix
mkdir -p $PREFIX
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
export PATH=$PREFIX/bin:$PATH

# Minimize gst-debug level/code
#export CFLAGS="$CFLAGS -DGST_LEVEL_MAX=2 -g -O0"
#export CXXFLAGS="$CXXFLAGS -DGST_LEVEL_MAX=2 -g -O0"
export CFLAGS="$CFLAGS -g -O0"
export CXXFLAGS="$CXXFLAGS -g -O0"

#DEBUGGING !!!
env
#
echo "CFLAGS : " $CFLAGS
echo "CXXFLAGS : " $CXXFLAGS
PLUGIN_DIR=$PREFIX/lib/gstreamer-1.0

# Switch to work directory
cd $WORK

# 1) BUILD GLIB AND GSTREAMER
# Note: we build glib ourselves so that we get proper malloc/free backtraces
tar xvJf $SRC/glib-2.56.1.tar.xz
cd glib-2.56.1
./configure --prefix=$PREFIX --enable-static --disable-shared --disable-libmount --with-pcre=internal --disable-always-build-tests && make -j$(nproc) && make install
cd ..

# Note: We don't use/build orc since it still seems to be problematic
# with clang and the various sanitizers.

# For now we only build core and base. Add other modules when/if needed
for i in gstreamer gst-plugins-base gst-plugins-good;
do
    mkdir -p $i
    cd $i
    $SRC/$i/autogen.sh --prefix=$PREFIX --disable-shared --enable-static --disable-examples \
		       --disable-gtk-doc --disable-introspection --enable-static-plugins \
		       --disable-gst-tracer-hooks --disable-registry
    make -j$(nproc)
    make install
    cd ..
done



# 2) Build the target fuzzers

# All targets will be linked in with $LIB_FUZZING_ENGINE which contains the
# actual fuzzing runner. Anything fuzzing engine can be used provided it calls
# the same function as libfuzzer.

# Note: The fuzzer .o needs to be first compiled with CC and then linked with CXX

# We want to statically link everything, except for shared libraries
# that are present on the base image. Those need to be specified
# beforehand and explicitely linked dynamically If any of the static
# dependencies require a pre-installed shared library, you need to add
# that library to the following list
PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -pthread -lrt -lpthread"

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

TARGET_DEPS=" gstreamer-pbutils-1.0 \
	      gstreamer-video-1.0 \
	      gstreamer-audio-1.0 \
	      gstreamer-riff-1.0 \
	      gstreamer-tag-1.0 \
	      zlib ogg vorbis vorbisenc \
	      theoraenc theoradec theora"

PLUGINS="$PLUGIN_DIR/libgstcoreelements.a \
       $PLUGIN_DIR/libgsttypefindfunctions.a \
       $PLUGIN_DIR/libgstplayback.a \
       $PLUGIN_DIR/libgstapp.a \
       $PLUGIN_DIR/libgstvorbis.a \
       $PLUGIN_DIR/libgsttheora.a \
       $PLUGIN_DIR/libgstogg.a"

echo
echo ">>>> BUILDING gst-discoverer"
echo
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $COMMON_DEPS $TARGET_DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $COMMON_DEPS $TARGET_DEPS`"

$CC $CFLAGS $BUILD_CFLAGS -c $SRC/gst-ci/fuzzing/gst-discoverer.c -o $SRC/gst-ci/fuzzing/gst-discoverer.o
$CXX $CXXFLAGS \
      -o $OUT/gst-discoverer \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/gst-discoverer.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic
echo
echo ">>>> BUILDING gst-discoverer_pull"
echo

$CC $CFLAGS $BUILD_CFLAGS -DPULL_MODE_FUZZER -c $SRC/gst-ci/fuzzing/gst-discoverer.c -o $SRC/gst-ci/fuzzing/gst-discoverer.o
$CXX $CXXFLAGS \
      -o $OUT/gst-discoverer_pull \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/gst-discoverer.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

#
# TARGET : push-based typefind
#

# typefindfunction depends on pbutils which depends on gst{audio|video|tag}
TARGET_DEPS=" gstreamer-pbutils-1.0 \
	      gstreamer-video-1.0 \
	      gstreamer-audio-1.0 \
	      gstreamer-tag-1.0"

PLUGINS="$PLUGIN_DIR/libgstcoreelements.a \
       $PLUGIN_DIR/libgsttypefindfunctions.a \
       $PLUGIN_DIR/libgstapp.a"

echo
echo ">>>> BUILDING typefind"
echo
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $COMMON_DEPS $TARGET_DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $COMMON_DEPS $TARGET_DEPS`"

$CC $CFLAGS $BUILD_CFLAGS -c $SRC/gst-ci/fuzzing/typefind.c -o $SRC/gst-ci/fuzzing/typefind.o
$CXX $CXXFLAGS \
      -o $OUT/typefind \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/typefind.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

echo
echo ">>>> BUILDING typefind_pull"
echo

$CC $CFLAGS $BUILD_CFLAGS -DPULL_MODE_FUZZER -c $SRC/gst-ci/fuzzing/typefind.c -o $SRC/gst-ci/fuzzing/typefind.o
$CXX $CXXFLAGS \
      -o $OUT/typefind_pull \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/typefind.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

echo
echo ">>>> Installing seed corpus"
echo
# FIXME : Sadly we apparently need to have the corpus downloaded in the
#         Dockerfile and not here.

cp $SRC/*_seed_corpus.zip $OUT
