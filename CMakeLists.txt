cmake_minimum_required(VERSION 3.10)
project(func_extractor LANGUAGES CXX)

# 設定 C++ 標準
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 生成 compile_commands.json（LibTooling 需要）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(PREPEND CMAKE_PREFIX_PATH "$ENV{CONDA_PREFIX}")

# 1. 尋找 LLVM 和 Clang 套件
# 這裡不需要指定路徑，我們會透過指令參數告訴 CMake 去哪裡找
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM_DIR = ${LLVM_DIR}")
message(STATUS "Clang_DIR = ${Clang_DIR}")

# 2. 設定 Header 搜尋路徑
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# 3. 建立執行檔
add_executable(func_extractor src/main.cpp)

# 針對 Linux 系統可能需要 linking pthread 等系統庫
# llvm_map_components_to_libnames(LLVM_LIBS Support)

# 4. 連結必要的 Libraries
# 這些是開發 LibTooling 必備的組件
target_link_libraries(func_extractor
  PRIVATE
  clang-cpp
  LLVM
)
