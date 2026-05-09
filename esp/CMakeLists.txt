# gateway-provisioning ESP-IDF project root.
# SCADABLE 2026 · Apache-2.0
#
# Standard ESP-IDF v5.1+ top-level CMakeLists. The actual sources are
# registered by main/CMakeLists.txt. Component dependencies (libscadable,
# wifi_provisioning) are pulled by IDF Component Manager from
# main/idf_component.yml.

cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(gateway-provisioning)
