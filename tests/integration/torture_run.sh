#! /bin/sh

while true ; do
    # Regenerate keys
    echo "🔑 Regenerating test keys..."
    rm -v user_keys/*
    make
    ../../../tests/integration/tests.sh
    if [ $? -ne 0 ]; then
        echo "❌ Tests failed. Exiting torture run."
        exit 1
    fi
    echo "✅ All tests passed. Restarting tests..."
done