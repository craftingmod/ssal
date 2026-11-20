cmake_minimum_required(VERSION 3.22.1)
project(ssal_presenter LANGUAGES CXX)

add_library(ssal_presenter SHARED
    presenter_jni.cpp
)

target_compile_features(ssal_presenter PRIVATE cxx_std_17)
target_compile_options(ssal_presenter PRIVATE -Wall -Wextra -Werror)

find_library(android-lib android REQUIRED)
find_library(egl-lib EGL REQUIRED)
find_library(gles2-lib GLESv2 REQUIRED)
find_library(log-lib log REQUIRED)

target_link_libraries(ssal_presenter
    ${android-lib}
    ${egl-lib}
    ${gles2-lib}
    ${log-lib}
    dl
)
