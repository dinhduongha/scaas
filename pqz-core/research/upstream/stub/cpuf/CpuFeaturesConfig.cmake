add_library(CpuFeatures::cpu_features INTERFACE IMPORTED)
set_target_properties(CpuFeatures::cpu_features PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}/include")
