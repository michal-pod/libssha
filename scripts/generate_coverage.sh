#!/bin/bash
BUILD_DIR=build
OUTPUT_FILE=coverage/lcov.info


# clean build
find $BUILD_DIR -type f \( -name '*.gcda' -o -name '*.gcno' -o -name '*.gcov' \) -exec rm -v {} +

make -C $BUILD_DIR clean
make -C $BUILD_DIR -j 4

# Create coverage directory if it doesn't exist
mkdir -p coverage

# Run unit tests
ctest --test-dir $BUILD_DIR

# Run integration tests
(cd build/tests/integration && ../../../tests/integration/tests.sh)

# Collect coverage data
gcovr -r . --exclude 'build/_deps' --xml-pretty --output $OUTPUT_FILE

gcovr -r . --exclude 'build/_deps' --txt

echo "Coverage report generated at $OUTPUT_FILE"