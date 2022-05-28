cmake_minimum_required (VERSION 3.12)
set (PROJECT_NAME "NoIAT")
project (${PROJECT_NAME} VERSION 0.0.1)
set(CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_STANDARD 17)

enable_language(ASM_NASM)
SET(ASM_DIALECT "-NASM")
set(CMAKE_ASM_NASM_SOURCE_FILE_EXTENSIONS "asm;nasm;S")

set (CXX_COMPILER_FLAGS "-w -g")
set (CXX_LINKER_FLAGS "")


set (EXECUTABLE_NAME ${PROJECT_NAME})
set (SOURCE_FILES src/main.cpp src/parser.cpp src/utils.cpp src/noiat_stub32.nasm src/noiat_stub64.nasm)

if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LARGEADDRESSAWARE")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LARGEADDRESSAWARE")
endif()

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILER_FLAGS}")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CXX_LINKER_FLAGS}")

find_package(Git REQUIRED)

if (NOT EXISTS "${CMAKE_SOURCE_DIR}/cryptopp")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" clone https://github.com/weidai11/cryptopp.git
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
endif()
if(WIN32)
    string(APPEND CMAKE_ASM_NASM_FLAGS "-dWIN32=1")
endif(WIN32)

set(CMAKE_SKIP_INSTALL_RULES TRUE)
add_subdirectory(cryptopp)

add_executable (${EXECUTABLE_NAME} ${SOURCE_FILES})

target_link_libraries (${EXECUTABLE_NAME} cryptopp-static)

install( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )