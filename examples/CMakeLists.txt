if(UNIX)
add_executable(test-agent test-agent.cpp)
target_link_libraries(test-agent ssha ${BOTAN_LIBRARIES})

endif()

if(WIN32)
add_executable(test-agent test-agent-win.cpp)
target_link_libraries(test-agent ssha ${BOTAN_LIBRARIES} ws2_32)
endif()

