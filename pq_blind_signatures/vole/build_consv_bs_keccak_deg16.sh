#!/bin/bash


# copying the main meson.build file to inside faest-cpp-tmp
MAIN_MESON_SOURCE_FILE="meson.build"
MAIN_MESON_DESTINATION="faest-cpp-tmp/meson.build"
cp "$MAIN_MESON_SOURCE_FILE" "$MAIN_MESON_DESTINATION"

# copying the test meson.build and the other test files
TEST_MESON_SOURCE_FILE="conservative_bs/test/meson.build"
TEST_MESON_DESTINATION="faest-cpp-tmp/test/meson.build"
cp "$TEST_MESON_SOURCE_FILE" "$TEST_MESON_DESTINATION"

# These are the file that we need to replace in FAEST-CPP

# PARAMETERS.HPP
PARAMETERS_SOURCE_FILE="conservative_bs/parameters.hpp"
PARAMETERS_DESTINATION="faest-cpp-tmp/parameters.hpp"
cp "$PARAMETERS_SOURCE_FILE" "$PARAMETERS_DESTINATION"
sed -i '1i#define KECCAK_DEG_16' "$PARAMETERS_DESTINATION"
sed -i '1i#define PLUS_MAYO' "$PARAMETERS_DESTINATION"
sed -i '1i#define WITH_KECCAK' "$PARAMETERS_DESTINATION"

# CONSTANTS.HPP
CONSTANTS_SOURCE_FILE="conservative_bs/constants.hpp"
CONSTANTS_DESTINATION="faest-cpp-tmp/constants.hpp"
cp "$CONSTANTS_SOURCE_FILE" "$CONSTANTS_DESTINATION"

# OWF_PROOF.CPP/HPP/INC
OWF_CPP_SOURCE_FILE="conservative_bs/owf_proof.cpp"
OWF_CPP_DESTINATION="faest-cpp-tmp/owf_proof.cpp"
cp "$OWF_CPP_SOURCE_FILE" "$OWF_CPP_DESTINATION"
OWF_HPP_SOURCE_FILE="conservative_bs/owf_proof.hpp"
OWF_HPP_DESTINATION="faest-cpp-tmp/owf_proof.hpp"
cp "$OWF_HPP_SOURCE_FILE" "$OWF_HPP_DESTINATION"
OWF_INC_SOURCE_FILE="conservative_bs/owf_proof.inc"
OWF_INC_DESTINATION="faest-cpp-tmp/owf_proof.inc"
cp "$OWF_INC_SOURCE_FILE" "$OWF_INC_DESTINATION"

# FAEST_KEYS.HPP/INC
FAEST_KEYS_HPP_SOURCE_FILE="conservative_bs/faest_keys.hpp"
FAEST_KEYS_HPP_DESTINATION="faest-cpp-tmp/faest_keys.hpp"
cp "$FAEST_KEYS_HPP_SOURCE_FILE" "$FAEST_KEYS_HPP_DESTINATION"
FAEST_KEYS_INC_SOURCE_FILE="conservative_bs/faest_keys.inc"
FAEST_KEYS_INC_DESTINATION="faest-cpp-tmp/faest_keys.inc"
cp "$FAEST_KEYS_INC_SOURCE_FILE" "$FAEST_KEYS_INC_DESTINATION"

# FAEST.CPP/HPP/INC
FAEST_CPP_SOURCE_FILE="conservative_bs/faest.cpp"
FAEST_CPP_DESTINATION="faest-cpp-tmp/faest.cpp"
cp "$FAEST_CPP_SOURCE_FILE" "$FAEST_CPP_DESTINATION"

FAEST_HPP_SOURCE_FILE="conservative_bs/faest.hpp"
FAEST_HPP_DESTINATION="faest-cpp-tmp/faest.hpp"
cp "$FAEST_HPP_SOURCE_FILE" "$FAEST_HPP_DESTINATION"

FAEST_INC_SOURCE_FILE="conservative_bs/faest.inc"
FAEST_INC_DESTINATION="faest-cpp-tmp/faest.inc"
cp "$FAEST_INC_SOURCE_FILE" "$FAEST_INC_DESTINATION"

# SMALL_VOLE.CPP
SMALL_VOLE_SOURCE_FILE="conservative_bs/small_vole.cpp"
SMALL_VOLE_DESTINATION="faest-cpp-tmp/small_vole.cpp"
cp "$SMALL_VOLE_SOURCE_FILE" "$SMALL_VOLE_DESTINATION"

# VOLE_COMMIT.CPP
VOLE_COMMIT_SOURCE_FILE="conservative_bs/vole_commit.cpp"
VOLE_COMMIT_DESTINATION="faest-cpp-tmp/vole_commit.cpp"
cp "$VOLE_COMMIT_SOURCE_FILE" "$VOLE_COMMIT_DESTINATION"

# TEST.HPP
TEST_SOURCE_FILE="conservative_bs/test/test.hpp"
TEST_DESTINATION="faest-cpp-tmp/test/test.hpp"
cp "$TEST_SOURCE_FILE" "$TEST_DESTINATION"

# TEST_VOLEMAYO.HPP
TEST_VOLEMAYO_SOURCE_FILE="conservative_bs/test/test_voleconsv_bs.cpp"
TEST_VOLEMAYO_DESTINATION="faest-cpp-tmp/test/test_voleconsv_bs.cpp"
cp "$TEST_VOLEMAYO_SOURCE_FILE" "$TEST_VOLEMAYO_DESTINATION"

# FIPS202.H
FIPS202H_SOURCE_FILE="common/fips202.h"
FIPS202H_DESTINATION="faest-cpp-tmp/test/fips202.h"
cp "$FIPS202H_SOURCE_FILE" "$FIPS202H_DESTINATION"

# FIPS202.C
FIPS202C_SOURCE_FILE="common/fips202.c"
FIPS202C_DESTINATION="faest-cpp-tmp/test/fips202.c"
cp "$FIPS202C_SOURCE_FILE" "$FIPS202C_DESTINATION"
# NOTE: Inserting deg 16 defined!!
sed -i '1i#define KECCAK_DEG_16' "$FIPS202C_DESTINATION"

# OWF_PROOF_TOOLS.HPP
OWF_PROOF_TOOLS_SOURCE_FILE="conservative_bs/owf_proof_tools.hpp"
OWF_PROOF_TOOLS_DESTINATION="faest-cpp-tmp/owf_proof_tools.hpp"
cp "$OWF_PROOF_TOOLS_SOURCE_FILE" "$OWF_PROOF_TOOLS_DESTINATION"

# POLYNOMIALS_IMPL.HPP
POLYNOMIALS_IMPL_SOURCE_FILE="conservative_bs/avx2/polynomials_impl.hpp"
POLYNOMIALS_IMPL_DESTINATION="faest-cpp-tmp/avx2/polynomials_impl.hpp"
cp "$POLYNOMIALS_IMPL_SOURCE_FILE" "$POLYNOMIALS_IMPL_DESTINATION"

# POLYNOMIALS_CONSTANTS.CPP
POLYNOMIALS_CONSTANTS_CPP_SOURCE_FILE="conservative_bs/polynomials_constants.cpp"
POLYNOMIALS_CONSTANTS_CPP_DESTINATION="faest-cpp-tmp/polynomials_constants.cpp"
cp "$POLYNOMIALS_CONSTANTS_CPP_SOURCE_FILE" "$POLYNOMIALS_CONSTANTS_CPP_DESTINATION"

# POLYNOMIALS_CONSTANTS.HPP
POLYNOMIALS_CONSTANTS_HPP_SOURCE_FILE="conservative_bs/polynomials_constants.hpp"
POLYNOMIALS_CONSTANTS_HPP_DESTINATION="faest-cpp-tmp/polynomials_constants.hpp"
cp "$POLYNOMIALS_CONSTANTS_HPP_SOURCE_FILE" "$POLYNOMIALS_CONSTANTS_HPP_DESTINATION"

# QUICKSILVER.HPP
QUICKSILVER_HPP_SOURCE_FILE="conservative_bs/quicksilver.hpp"
QUICKSILVER_HPP_DESTINATION="faest-cpp-tmp/quicksilver.hpp"
cp "$QUICKSILVER_HPP_SOURCE_FILE" "$QUICKSILVER_HPP_DESTINATION"

# Copy over the fast.h file as a header for the rust wrappings
FAEST_H_SOURCE_FILE="conservative_bs/faest.h"
FAEST_H_DESTINATION="faest-cpp-tmp/faest.h"
cp "$FAEST_H_SOURCE_FILE" "$FAEST_H_DESTINATION"

# compiling faest-cpp-tmp with the new added meson.build
export SHAREDLIBNAME="volekeccak_deg16_then_mayo_bs"
export ARFLAGS=rcs
cd faest-cpp-tmp
# meson setup build_debug --buildtype=debug
meson setup build_debug --buildtype=release
cd build_debug
meson compile
