cmake_minimum_required(VERSION 3.0)

##set(CMAKE_CXX_COMPILER "/opt/rh/devtoolset-8/root/bin/g++")
##set(CMAKE_C_COMPILER "/opt/rh/devtoolset-8/root/bin/gcc")


project (sdk) 

set(CMAKE_CXX_STANDARD 17)

#        Debug or Release
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -rdynamic")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -rdynamic")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -rdynamic")
set(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -rdynamic")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

message("CMAKE_BUILD_TYPE is:${CMAKE_BUILD_TYPE}")



if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE must be Debug or Release!!!")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_definitions(-Wno-builtin-macro-redefined)

#add_definitions(-w)

#       
set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CMAKE_COMMAND} -E time")

set(CXX_FLAGS
        -Wall  
	-g
        )

 add_compile_options(-g -fPIC)
 
SET(ROOT_DIR ${CMAKE_SOURCE_DIR})
link_directories(${ROOT_DIR}/build/)

execute_process(COMMAND sh ${ROOT_DIR}/make_depend.sh ${CMAKE_CURRENT_BINARY_DIR})

if(PRIMARYCHAIN)
    ADD_DEFINITIONS(-DPRIMARYCHAIN)
elseif(TESTCHAIN)
    ADD_DEFINITIONS(-DTESTCHAIN)
else()
    ADD_DEFINITIONS(-DDEVCHAIN)
endif()

#       
file(GLOB SOURCES 
    "*.cpp"
    "api/*.cpp"
    "include/*.cpp" 
    "utils/*.cpp"
    "utils/json/*.cpp"
    "utils/*.c"
    "ca/*.cpp"
    "db/*.cpp"
    "net/*.cpp"
    "common/*.cpp"
    "proto/*.cc"
    "mpt/*.cpp"
    "mpt/*.cpp"
    )

file(GLOB CA_SO "global_so/*.cpp")


# test   
file(GLOB_RECURSE TEST_SOURCE tests/*.cpp)
#message(${TEST_SOURCE})


add_library(${PROJECT_NAME} SHARED ${SOURCES})



include (utils.cmake)
redefine_file_macro(${PROJECT_NAME})




set(EXECUTABLE_OUTPUT_PATH bin)
#     
include_directories("${ROOT_DIR}/")
include_directories("${ROOT_DIR}/ca")
include_directories("${ROOT_DIR}/include")
include_directories("${ROOT_DIR}/mpt")
include_directories("${ROOT_DIR}/rocksdb/include")
include_directories("${ROOT_DIR}/protobuf/src")
include_directories("${ROOT_DIR}/proto")
include_directories("${ROOT_DIR}/spdlog/include")
include_directories("${ROOT_DIR}/openssl/include")



#      
target_link_libraries(${PROJECT_NAME}  dl)
target_link_libraries(${PROJECT_NAME}  z)

target_link_libraries(${PROJECT_NAME} -pthread ) 







add_library(protobuf STATIC IMPORTED)
#set_property(TARGET protobuf PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/protobuf/cmake/libprotobuf.a)
set_property(TARGET protobuf PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/protobuf/src/.libs/libprotobuf.so)
target_link_libraries(${PROJECT_NAME}  protobuf )


#add_library(ca STATIC  ${CA_SO})
#set_property(TARGET ca PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/bulid/libca.a)
target_link_libraries(${PROJECT_NAME}  ca )

add_library(openssl SHARED IMPORTED)
set_property(TARGET openssl PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/openssl/libssl.so)
set_property(TARGET openssl PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/openssl/libcrypto.so)
target_link_libraries(${PROJECT_NAME}  openssl )


find_package(GTest)
if(GTEST_FOUND)
    # GTEST_INCLUDE_DIRS:/usr/local/include
    # message("GTEST_INCLUDE_DIRS:${GTEST_INCLUDE_DIRS}")
    include_directories(${GTEST_INCLUDE_DIRS})
    add_executable(test EXCLUDE_FROM_ALL ${SOURCES} ${TEST_SOURCE})
    
    # GTEST_BOTH_LIBRARIES:/usr/local/lib64/libgtest.a;/usr/local/lib64/libgtest_main.a
    message("GTEST_BOTH_LIBRARIES:${GTEST_BOTH_LIBRARIES}")
    # CMAKE_THREAD_LIBS_INIT:-lpthread, gtest      
    message("CMAKE_THREAD_LIBS_INIT:${CMAKE_THREAD_LIBS_INIT}")

    target_link_libraries(test ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

    target_link_libraries(test  dl)
    target_link_libraries(test  z)
    target_link_libraries(test  bz2)
    target_link_libraries(test  pthread ) 
    target_link_libraries(test  crypto )
    target_link_libraries(test  rocksdb )
    target_link_libraries(test  protobuf )
    target_link_libraries(test  spdlog)
    target_link_libraries(test  openssl)

endif(GTEST_FOUND)

if(PRIMARYCHAIN)
    ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh 0 ${CMAKE_CURRENT_BINARY_DIR}
    )
elseif(TESTCHAIN)
    ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh 1 ${CMAKE_CURRENT_BINARY_DIR}
    )
else()
    ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh 2 ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()






add_executable (main   main.cpp)
add_dependencies(main sdk)
target_link_libraries(main sdk pthread)




# install(CODE "execute_process(COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh)")
