#! /bin/sh


start_sshd() {
    INSTANCE_NAME=$1
    PORT=$2
    echo "🚀 Starting sshd for instance: $INSTANCE_NAME on port $PORT"
    /usr/sbin/sshd -f ${INSTANCE_NAME}/sshd_config
    while [ ! -f ${INSTANCE_NAME}/sshd.pid ]; do
        sleep 0.1
    done

    if nc -z localhost $PORT ; then
        echo "🟢 sshd $INSTANCE_NAME is listening on port $PORT."
    else
        echo "❌ sshd $INSTANCE_NAME failed to start."
        exit 1
    fi
}

stop_sshd() {
    INSTANCE_NAME=$1
    echo "🛑 Stopping sshd for instance: $INSTANCE_NAME"
    if [ -f ${INSTANCE_NAME}/sshd.pid ]; then
        PID=$(cat ${INSTANCE_NAME}/sshd.pid)
        kill $PID && wait $PID 2>/dev/null
        rm -f ${INSTANCE_NAME}/sshd.pid
        echo "🟢 sshd $INSTANCE_NAME stopped."
    else
        echo "⚠️ sshd $INSTANCE_NAME is not running."
    fi
}

setup() {
    echo "🔧 Setting up integration test environment..."
    start_sshd "host_a" 2222
    start_sshd "host_b" 2223
    start_sshd "host_c" 2224
    echo "🚦 Starting test-agent.."
    rm -fv /tmp/test-socket
    LIBSSHA_LOG_COLORS=0 valgrind --log-file=valgrind.log --leak-check=full --show-reachable=yes ../../examples/test-agent  2>> agent.log &
    #LIBSSHA_LOG_COLORS=0  ../../examples/test-agent  2>> agent.log &
    while [ ! -S /tmp/test-socket ]; do
        sleep 0.1
    done    
    AGENT_PID=$!
    export SSH_AUTH_SOCK=/tmp/test-socket
    echo "🟢 Test-agent started with PID $AGENT_PID"
    echo -n $AGENT_PID > test-agent.pid

    # Generate known_hosts file
    echo "🔑 Generating known_hosts file..."
    rm -f home/.ssh/known_hosts
    ssh-keyscan -p 2222 127.0.0.1 >> home/.ssh/known_hosts 2>/dev/null
    ssh-keyscan -p 2223 127.0.0.1 >> home/.ssh/known_hosts 2>/dev/null
    ssh-keyscan -p 2224 127.0.0.1 >> home/.ssh/known_hosts 2>/dev/null
    echo "🟢 known_hosts file generated."
    export HOME=$(pwd)/home
    export FAKE_HOME=$(pwd)/home
    export LD_PRELOAD=$(pwd)/libhome_replace.so
    echo "🟢 Integration test environment setup complete."

}

teardown() {
    echo "🧹 Tearing down integration test environment..."
    stop_sshd "host_a"
    stop_sshd "host_b"
    stop_sshd "host_c"
    if [ -f test-agent.pid ]; then
        AGENT_PID=$(cat test-agent.pid)
        echo "🛑 Stopping test-agent with PID $AGENT_PID"
        kill $AGENT_PID && wait $AGENT_PID 2>/dev/null
        rm -f test-agent.pid
        echo "🟢 Test-agent stopped."
    fi
}

test_expected_output() {
    NAME=$1    
    COMMAND=$2
    EXPECTED_OUTPUT=$3

    echo "🧪 Running test: $NAME"
    OUTPUT=$(eval $COMMAND 2>&1)
    if echo "$OUTPUT" | grep -q "$EXPECTED_OUTPUT"; then
        echo "✅ Test $NAME passed."
        #sleep 1
    else
        echo "❌ Test $NAME failed."
        echo "🔴 Expected: $EXPECTED_OUTPUT"
        echo "🔴 Got: $OUTPUT"
        exit 1
    fi
}

test_successful_command() {
    NAME=$1
    COMMAND=$2

    echo "🧪 Running test: $NAME" 
    eval $COMMAND 2> /dev/null > /dev/null
    if [ $? -eq 0 ]; then
        echo "✅ Test $NAME passed."
        #sleep 1
    else
        echo "❌ Test $NAME failed."
        exit 1
    fi
}

test_failed_command() {
    NAME=$1
    COMMAND=$2

    echo "🧪 Running test: $NAME" 
    eval $COMMAND 2> /dev/null > /dev/null
    if [ $? -ne 0 ]; then
        echo "✅ Test $NAME passed."
        #sleep 1
    else
        echo "❌ Test $NAME failed."
        exit 1
    fi
}

test_expected_output_lines() {
    NAME=$1
    COMMAND=$2
    EXPECTED_LINES=$3

    #echo "🧪 Running test: $NAME"
    OUTPUT=$(eval $COMMAND 2>/dev/null )
    ACTUAL_LINES=$(echo "$OUTPUT" | wc -l)
    if [ "$ACTUAL_LINES" -eq "$EXPECTED_LINES" ]; then
        echo "✅ Test $NAME passed."
        #sleep 1
    else
        echo "❌ Test $NAME failed."
        echo "🔴 Expected lines: $EXPECTED_LINES"
        echo "🔴 Got lines: $ACTUAL_LINES"
        echo "🔴 Output: $OUTPUT"
        exit 1
    fi
}

trap teardown EXIT
setup

#sleep 30
#export SSH_AUTH_SOCK=/tmp/test-socket
test_expected_output "Agent Running Test" "ssh-add -l" "The agent has no identities."
test_successful_command "Add RSA key" "ssh-add user_keys/test_rsa"
test_successful_command "Add ECDSA 256 key" "ssh-add user_keys/test_ecdsa256"
test_successful_command "Add ECDSA 384 key" "ssh-add user_keys/test_ecdsa384"
test_successful_command "Add ECDSA 521 key" "ssh-add user_keys/test_ecdsa521"
test_successful_command "Add ED25519 key" "ssh-add user_keys/test_ed25519"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_expected_output "Attempt to use locked agent" "ssh-add -l" "error fetching identities: agent refused operation"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output_lines "List keys after unlocking agent" "ssh-add -l" 5
test_successful_command "Remove all keys" "ssh-add -D"


# Test connecting to host_a using RSA key
test_successful_command "Add RSA key" "ssh-add user_keys/test_rsa"
test_expected_output "Connect using RSA key" "ssh host_a echo connected_to_host_a" "connected_to_host_a"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output "Connect using RSA key after unlocking" "ssh host_a echo connected_to_host_a" "connected_to_host_a"
test_successful_command "Remove RSA key" "ssh-add -d user_keys/test_rsa"

# Test connecting to host_b using ECDSA 256 key
test_successful_command "Add ECDSA 256 key" "ssh-add user_keys/test_ecdsa256"
test_expected_output "Connect using ECDSA 256 key" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output "Connect using ECDSA 256 key after unlocking" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Remove ECDSA 256 key" "ssh-add -d user_keys/test_ecdsa256"

# Test connecting to host_b using ECDSA 384 key
test_successful_command "Add ECDSA 384 key" "ssh-add user_keys/test_ecdsa384"
test_expected_output "Connect using ECDSA 384 key" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output "Connect using ECDSA 384 key after unlocking" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Remove ECDSA 384 key" "ssh-add -d user_keys/test_ecdsa384"

# Test connecting to host_b using ECDSA 521 key
test_successful_command "Add ECDSA 521 key" "ssh-add user_keys/test_ecdsa521"
test_expected_output "Connect using ECDSA 521 key" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output "Connect using ECDSA 521 key after unlocking" "ssh host_b echo connected_to_host_b" "connected_to_host_b"
test_successful_command "Remove ECDSA 521 key" "ssh-add -d user_keys/test_ecdsa521" 

# Test connecting to host_c using ED25519 key
test_successful_command "Add ED25519 key" "ssh-add user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key" "ssh host_c echo connected_to_host_c" "connected_to_host_c"
test_successful_command "Lock agent" "./lock_unlock_agent lock"
test_successful_command "Unlock agent" "./lock_unlock_agent unlock"
test_expected_output "Connect using ED25519 key after unlocking" "ssh host_c echo connected_to_host_c" "connected_to_host_c"
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for working constraints
test_successful_command "Add ED25519 key" "ssh-add -h '[127.0.0.1]:2222' user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with correct host constraint" "ssh host_a echo connected_to_host_a" "connected_to_host_a"
test_expected_output "Connect using ED25519 key with incorrect host constraint" "ssh host_b echo connected_to_host_b" "Permission denied (publickey)."
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for working constraints with forwarded agent
test_successful_command "Add ED25519 key" "ssh-add -h '[127.0.0.1]:2224' -h '[127.0.0.1]:2224>[127.0.0.1]:2222' user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with correct host constraint via forwarded agent" "ssh host_c ssh -v host_a echo connected_to_host_a_via_forwarded_agent" "connected_to_host_a_via_forwarded_agent"
test_expected_output "Connect using ED25519 key with incorrect host constraint via forwarded agent" "ssh host_c ssh host_b echo connected_to_host_b_via_forwarded_agent" "Permission denied (publickey)."
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for constraints with user name
test_successful_command "Add ED25519 key" "ssh-add -h "$USER@[127.0.0.1]:2222" user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with correct user constraint" "ssh host_a echo connected_to_host_a" "connected_to_host_a"
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for constraints with invalid user name
test_successful_command "Add ED25519 key" "ssh-add -h "invaliduser@[127.0.0.1]:2222" user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with incorrect user constraint" "ssh host_a echo connected_to_host_a" "Permission denied (publickey)."
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for constraints with 2 hops
test_successful_command "Add ED25519 key" "ssh-add -h '[127.0.0.1]:2222' -h '[127.0.0.1]:2222>[127.0.0.1]:2223' -h '[127.0.0.1]:2223>[127.0.0.1]:2224'  user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with correct 2-hop constraint" "ssh host_a ssh host_b ssh host_c echo connected_to_host_c_via_2_hops" "connected_to_host_c_via_2_hops"
test_successful_command "Remove ED25519 key" "ssh-add -d user_keys/test_ed25519"

# Test for keys visibility on forwarded agent
test_successful_command "Add RSA key" "ssh-add user_keys/test_rsa" # should always be visible
test_successful_command "Add ED25519 key" "ssh-add -h '[127.0.0.1]:2222' -h '[127.0.0.1]:2222>[127.0.0.1]:2223' user_keys/test_ed25519"
test_successful_command "Add ECDSA 256 key" "ssh-add -h '[127.0.0.1]:2222' -h '[127.0.0.1]:2222>[127.0.0.1]:2223' user_keys/test_ecdsa256"
test_expected_output_lines "List keys on forwarded agent" "ssh host_a ssh-add -l" 3
test_expected_output_lines "List keys on forwarded agent" "ssh host_b ssh-add -l" 1
test_successful_command "Remove all keys" "ssh-add -D"

# 5. Cycle denial (add constraints that do not allow cycles)
test_successful_command "Add ED25519 key with cycle-deny constraints" \
    "ssh-add -h '[127.0.0.1]:2222' -h '[127.0.0.1]:2222>[127.0.0.1]:2223' user_keys/test_ed25519"
test_expected_output "Connect using ED25519 key with cycle-deny constraints" \
    "ssh host_a ssh host_b ssh host_a echo connected_to_host_a_via_cycle_deny_constraints" \
    "Permission denied (publickey)."
test_successful_command "Remove ED25519 key with cycle-deny constraints" "ssh-add -d user_keys/test_ed25519" 

# Unlocking unlocked agent should fail - section 3.7 of agent protocol draft
test_failed_command "Unlocking already unlocked agent should fail" "./lock_unlock_agent unlock"


sleep 2
