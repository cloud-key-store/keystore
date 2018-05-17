project(keystore)

cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${keystore_SOURCE_DIR}/ ${CMAKE_MODULE_PATH})
set(ALL_SRCS CACHE INTERNAL "description" FORCE)

enable_testing()
find_package(Check REQUIRED)

include_directories(${CHECK_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CHECK_LIBRARIES} pthread)
include_directories(. ../src/)
add_executable(check_sexp check_sexp.c ../src/sexp/sexp.c)
target_link_libraries(check_sexp ${LIBS})
add_test(check_sexp ${CMAKE_CURRENT_BINARY_DIR}/check_sexp)

include_directories(. ../src/ ../src/sexp /opt/intel/sgxsdk/include /opt/intel/ipp/inc)
add_executable(check_key check_key.cpp ../src/enclave/key.cpp)
set(LIBS ${LIBS} /opt/intel/sgxsdk/lib64/libsgx_tcrypto.a)
target_link_libraries(check_key ${LIBS})
add_test(check_key ${CMAKE_CURRENT_BINARY_DIR}/check_key)
