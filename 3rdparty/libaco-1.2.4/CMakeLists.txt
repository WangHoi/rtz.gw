set(aco_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
set(aco_LIBRARIES aco PARENT_SCOPE)
add_library(aco aco.c acosw.S)
target_compile_options(aco PUBLIC "-DACO_CONFIG_SHARE_FPU_MXCSR_ENV")
