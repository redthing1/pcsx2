include_guard(GLOBAL)

include(FetchContent)
include(CustomDepsVersions)

function(_pcsx2_customdeps_require_target target_name dep_name)
	if(NOT TARGET "${target_name}")
		message(FATAL_ERROR "CustomDeps failed to provide target '${target_name}' for ${dep_name}.")
	endif()
endfunction()

macro(_pcsx2_customdeps_push_build_shared_libs_on)
	set(_pcsx2_customdeps_prev_bsl_defined FALSE)
	if(DEFINED BUILD_SHARED_LIBS)
		set(_pcsx2_customdeps_prev_bsl_defined TRUE)
		set(_pcsx2_customdeps_prev_bsl_value "${BUILD_SHARED_LIBS}")
	endif()

	get_property(_pcsx2_customdeps_prev_bsl_cache_set CACHE BUILD_SHARED_LIBS PROPERTY TYPE SET)
	if(_pcsx2_customdeps_prev_bsl_cache_set)
		get_property(_pcsx2_customdeps_prev_bsl_cache_value CACHE BUILD_SHARED_LIBS PROPERTY VALUE)
	endif()

	set(BUILD_SHARED_LIBS ON)
	set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
endmacro()

macro(_pcsx2_customdeps_pop_build_shared_libs)
	if(_pcsx2_customdeps_prev_bsl_cache_set)
		set(BUILD_SHARED_LIBS "${_pcsx2_customdeps_prev_bsl_cache_value}" CACHE BOOL "" FORCE)
	else()
		unset(BUILD_SHARED_LIBS CACHE)
	endif()

	if(_pcsx2_customdeps_prev_bsl_defined)
		set(BUILD_SHARED_LIBS "${_pcsx2_customdeps_prev_bsl_value}")
	else()
		unset(BUILD_SHARED_LIBS)
	endif()

	unset(_pcsx2_customdeps_prev_bsl_cache_set)
	unset(_pcsx2_customdeps_prev_bsl_cache_value)
	unset(_pcsx2_customdeps_prev_bsl_defined)
	unset(_pcsx2_customdeps_prev_bsl_value)
endmacro()

macro(_pcsx2_customdeps_populate_archive dep_name dep_url dep_hash)
	FetchContent_GetProperties("${dep_name}")
	if(NOT ${dep_name}_POPULATED)
		set(_pcsx2_customdeps_dep_root "${CMAKE_BINARY_DIR}/_deps")
		set(_pcsx2_customdeps_dep_src "${_pcsx2_customdeps_dep_root}/${dep_name}-src")
		set(_pcsx2_customdeps_dep_bin "${_pcsx2_customdeps_dep_root}/${dep_name}-build")
		set(_pcsx2_customdeps_dep_subbuild "${_pcsx2_customdeps_dep_root}/${dep_name}-subbuild")
		FetchContent_Populate(
			"${dep_name}"
			SUBBUILD_DIR "${_pcsx2_customdeps_dep_subbuild}"
			SOURCE_DIR "${_pcsx2_customdeps_dep_src}"
			BINARY_DIR "${_pcsx2_customdeps_dep_bin}"
			URL "${dep_url}"
			URL_HASH "${dep_hash}"
		)
		unset(_pcsx2_customdeps_dep_root)
		unset(_pcsx2_customdeps_dep_src)
		unset(_pcsx2_customdeps_dep_bin)
		unset(_pcsx2_customdeps_dep_subbuild)
	endif()
endmacro()

function(_pcsx2_customdeps_replace_or_verify input_text old_snippet new_snippet out_var description)
	set(_pcsx2_text "${input_text}")
	string(FIND "${_pcsx2_text}" "${old_snippet}" _pcsx2_old_index)
	if(NOT _pcsx2_old_index EQUAL -1)
		string(REPLACE "${old_snippet}" "${new_snippet}" _pcsx2_text "${_pcsx2_text}")
	else()
		string(FIND "${_pcsx2_text}" "${new_snippet}" _pcsx2_new_index)
		if(_pcsx2_new_index EQUAL -1)
			message(FATAL_ERROR "CustomDeps shaderc patch failed (${description}).")
		endif()
	endif()

	set(${out_var} "${_pcsx2_text}" PARENT_SCOPE)
endfunction()

function(_pcsx2_customdeps_patch_shaderc_third_party third_party_cmake_path)
	file(READ "${third_party_cmake_path}" _pcsx2_shaderc_tp_contents)
	set(_pcsx2_shaderc_tp_original "${_pcsx2_shaderc_tp_contents}")
	_pcsx2_customdeps_replace_or_verify(
		"${_pcsx2_shaderc_tp_contents}"
		"set( SKIP_GLSLANG_INSTALL \${SHADERC_SKIP_INSTALL} )"
		"set( SKIP_GLSLANG_INSTALL ON )"
		_pcsx2_shaderc_tp_contents
		"SKIP_GLSLANG_INSTALL toggle")
	_pcsx2_customdeps_replace_or_verify(
		"${_pcsx2_shaderc_tp_contents}"
		"set( SKIP_SPIRV_TOOLS_INSTALL \${SHADERC_SKIP_INSTALL} )"
		"set( SKIP_SPIRV_TOOLS_INSTALL ON )"
		_pcsx2_shaderc_tp_contents
		"SKIP_SPIRV_TOOLS_INSTALL toggle")
	_pcsx2_customdeps_replace_or_verify(
		"${_pcsx2_shaderc_tp_contents}"
		"set( SKIP_GOOGLETEST_INSTALL \${SHADERC_SKIP_INSTALL} )"
		"set( SKIP_GOOGLETEST_INSTALL ON )"
		_pcsx2_shaderc_tp_contents
		"SKIP_GOOGLETEST_INSTALL toggle")
	_pcsx2_customdeps_replace_or_verify(
		"${_pcsx2_shaderc_tp_contents}"
		"set(GLSLANG_ENABLE_INSTALL $<NOT:\${SKIP_GLSLANG_INSTALL}>)"
		"set(GLSLANG_ENABLE_INSTALL OFF)"
		_pcsx2_shaderc_tp_contents
		"GLSLANG_ENABLE_INSTALL override")
	_pcsx2_customdeps_replace_or_verify(
		"${_pcsx2_shaderc_tp_contents}"
		"add_subdirectory(\${SHADERC_SPIRV_TOOLS_DIR} spirv-tools)"
		"set(SPIRV_SKIP_EXECUTABLES ON CACHE BOOL \"Skip building SPIRV-Tools executables\")\n    set(SPIRV_TOOLS_BUILD_STATIC OFF CACHE BOOL \"Skip building two SPIRV-Tools libs\")\n    set(SPIRV_TOOLS_LIBRARY_TYPE STATIC CACHE STRING \"Build static SPIRV-Tools libs\")\n    add_subdirectory(\${SHADERC_SPIRV_TOOLS_DIR} spirv-tools EXCLUDE_FROM_ALL)"
		_pcsx2_shaderc_tp_contents
		"SPIRV-Tools configuration override")
	if(NOT _pcsx2_shaderc_tp_contents STREQUAL _pcsx2_shaderc_tp_original)
		file(WRITE "${third_party_cmake_path}" "${_pcsx2_shaderc_tp_contents}")
	endif()
endfunction()

function(pcsx2_resolve_custom_dep_plutovg)
	find_package(plutovg 1.1.0 QUIET CONFIG)
	if(TARGET plutovg::plutovg)
		message(STATUS "CustomDeps: using system plutovg")
	else()
		message(STATUS "CustomDeps: fetching plutovg ${PCSX2_CUSTOM_DEP_PLUTOVG_VERSION}")
		set(PLUTOVG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
		_pcsx2_customdeps_push_build_shared_libs_on()
		FetchContent_Declare(
			pcsx2_custom_dep_plutovg
			URL "${PCSX2_CUSTOM_DEP_PLUTOVG_URL}"
			URL_HASH "${PCSX2_CUSTOM_DEP_PLUTOVG_HASH}"
		)
		FetchContent_MakeAvailable(pcsx2_custom_dep_plutovg)
		_pcsx2_customdeps_pop_build_shared_libs()
	endif()

	if(TARGET plutovg AND NOT TARGET plutovg::plutovg)
		add_library(plutovg::plutovg ALIAS plutovg)
	endif()
	_pcsx2_customdeps_require_target(plutovg::plutovg "plutovg")
endfunction()

function(pcsx2_resolve_custom_dep_plutosvg)
	find_package(plutosvg 0.0.7 QUIET CONFIG)
	if(TARGET plutosvg::plutosvg)
		message(STATUS "CustomDeps: using system plutosvg")
	else()
		message(STATUS "CustomDeps: fetching plutosvg ${PCSX2_CUSTOM_DEP_PLUTOSVG_VERSION}")
		if(TARGET plutovg::plutovg)
			set(plutovg_FOUND TRUE)
		endif()
		set(PLUTOSVG_ENABLE_FREETYPE ON CACHE BOOL "" FORCE)
		set(PLUTOSVG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
		_pcsx2_customdeps_push_build_shared_libs_on()
		FetchContent_Declare(
			pcsx2_custom_dep_plutosvg
			URL "${PCSX2_CUSTOM_DEP_PLUTOSVG_URL}"
			URL_HASH "${PCSX2_CUSTOM_DEP_PLUTOSVG_HASH}"
		)
		FetchContent_MakeAvailable(pcsx2_custom_dep_plutosvg)
		_pcsx2_customdeps_pop_build_shared_libs()
	endif()

	if(TARGET plutosvg AND NOT TARGET plutosvg::plutosvg)
		add_library(plutosvg::plutosvg ALIAS plutosvg)
	endif()
	_pcsx2_customdeps_require_target(plutosvg::plutosvg "plutosvg")
endfunction()

function(pcsx2_resolve_custom_dep_kddockwidgets)
	if(NOT ENABLE_QT_UI)
		return()
	endif()

	find_package(KDDockWidgets-qt6 2.3.0 QUIET CONFIG)
	if(TARGET KDAB::kddockwidgets)
		message(STATUS "CustomDeps: using system KDDockWidgets-qt6")
	else()
		if(NOT TARGET Qt6::Core)
			message(FATAL_ERROR "CustomDeps requires Qt6 to be resolved before KDDockWidgets.")
		endif()

		message(STATUS "CustomDeps: fetching KDDockWidgets ${PCSX2_CUSTOM_DEP_KDDOCKWIDGETS_VERSION}")
		set(KDDockWidgets_QT6 ON CACHE BOOL "" FORCE)
		set(KDDockWidgets_EXAMPLES OFF CACHE BOOL "" FORCE)
		set(KDDockWidgets_TESTS OFF CACHE BOOL "" FORCE)
		set(KDDockWidgets_FRONTENDS "qtwidgets" CACHE STRING "" FORCE)
		FetchContent_Declare(
			pcsx2_custom_dep_kddockwidgets
			URL "${PCSX2_CUSTOM_DEP_KDDOCKWIDGETS_URL}"
			URL_HASH "${PCSX2_CUSTOM_DEP_KDDOCKWIDGETS_HASH}"
		)
		FetchContent_MakeAvailable(pcsx2_custom_dep_kddockwidgets)
	endif()

	if(TARGET kddockwidgets AND NOT TARGET KDAB::kddockwidgets)
		add_library(KDAB::kddockwidgets ALIAS kddockwidgets)
	endif()
	if(TARGET kddockwidgets)
		if(MSVC)
			target_compile_options(kddockwidgets PRIVATE /EHsc)
		else()
			target_compile_options(kddockwidgets PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-fexceptions>")
		endif()
	endif()
	if(TARGET kddockwidgetsplugin)
		if(MSVC)
			target_compile_options(kddockwidgetsplugin PRIVATE /EHsc)
		else()
			target_compile_options(kddockwidgetsplugin PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-fexceptions>")
		endif()
	endif()
	_pcsx2_customdeps_require_target(KDAB::kddockwidgets "KDDockWidgets-qt6")
endfunction()

function(pcsx2_resolve_custom_dep_shaderc out_include_dir out_library_path)
	set(_shaderc_include_dir "")
	set(_shaderc_library_path "")

	find_package(Shaderc QUIET)
	if(TARGET Shaderc::shaderc_shared)
		message(STATUS "CustomDeps: using system shaderc")
		if(DEFINED SHADERC_INCLUDE_DIR AND SHADERC_INCLUDE_DIR)
			set(_shaderc_include_dir "${SHADERC_INCLUDE_DIR}")
		else()
			get_target_property(_shaderc_interface_includes Shaderc::shaderc_shared INTERFACE_INCLUDE_DIRECTORIES)
			if(_shaderc_interface_includes)
				list(GET _shaderc_interface_includes 0 _shaderc_include_dir)
			endif()
		endif()

		if(DEFINED SHADERC_LIBRARY AND SHADERC_LIBRARY)
			set(_shaderc_library_path "${SHADERC_LIBRARY}")
		endif()
	else()
		message(STATUS "CustomDeps: fetching shaderc ${PCSX2_CUSTOM_DEP_SHADERC_VERSION}")
		set(SHADERC_SKIP_INSTALL ON CACHE BOOL "" FORCE)
		set(SHADERC_SKIP_TESTS ON CACHE BOOL "" FORCE)
		set(SHADERC_SKIP_EXAMPLES ON CACHE BOOL "" FORCE)
		set(SHADERC_SKIP_EXECUTABLES ON CACHE BOOL "" FORCE)
		set(SHADERC_SKIP_COPYRIGHT_CHECK ON CACHE BOOL "" FORCE)
		set(SHADERC_ENABLE_WERROR_COMPILE OFF CACHE BOOL "" FORCE)

		set(SPIRV_SKIP_TESTS ON CACHE BOOL "" FORCE)
		set(SPIRV_SKIP_EXECUTABLES ON CACHE BOOL "" FORCE)

		_pcsx2_customdeps_populate_archive(
			pcsx2_custom_dep_shaderc_glslang
			"${PCSX2_CUSTOM_DEP_SHADERC_GLSLANG_URL}"
			"${PCSX2_CUSTOM_DEP_SHADERC_GLSLANG_HASH}"
		)
		_pcsx2_customdeps_populate_archive(
			pcsx2_custom_dep_shaderc_spirv_headers
			"${PCSX2_CUSTOM_DEP_SHADERC_SPIRV_HEADERS_URL}"
			"${PCSX2_CUSTOM_DEP_SHADERC_SPIRV_HEADERS_HASH}"
		)
		_pcsx2_customdeps_populate_archive(
			pcsx2_custom_dep_shaderc_spirv_tools
			"${PCSX2_CUSTOM_DEP_SHADERC_SPIRV_TOOLS_URL}"
			"${PCSX2_CUSTOM_DEP_SHADERC_SPIRV_TOOLS_HASH}"
		)

		set(SHADERC_GLSLANG_DIR "${pcsx2_custom_dep_shaderc_glslang_SOURCE_DIR}" CACHE PATH "" FORCE)
		set(SHADERC_SPIRV_HEADERS_DIR "${pcsx2_custom_dep_shaderc_spirv_headers_SOURCE_DIR}" CACHE PATH "" FORCE)
		set(SHADERC_SPIRV_TOOLS_DIR "${pcsx2_custom_dep_shaderc_spirv_tools_SOURCE_DIR}" CACHE PATH "" FORCE)

		_pcsx2_customdeps_populate_archive(
			pcsx2_custom_dep_shaderc
			"${PCSX2_CUSTOM_DEP_SHADERC_URL}"
			"${PCSX2_CUSTOM_DEP_SHADERC_HASH}"
		)
		_pcsx2_customdeps_patch_shaderc_third_party("${pcsx2_custom_dep_shaderc_SOURCE_DIR}/third_party/CMakeLists.txt")
		add_subdirectory("${pcsx2_custom_dep_shaderc_SOURCE_DIR}" "${pcsx2_custom_dep_shaderc_BINARY_DIR}" EXCLUDE_FROM_ALL)

		if(TARGET shaderc_shared AND NOT TARGET Shaderc::shaderc_shared)
			add_library(Shaderc::shaderc_shared ALIAS shaderc_shared)
		endif()

		set(_shaderc_include_dir "${pcsx2_custom_dep_shaderc_SOURCE_DIR}/libshaderc/include")
	endif()

	_pcsx2_customdeps_require_target(Shaderc::shaderc_shared "shaderc")

	if(NOT _shaderc_library_path)
		set(_shaderc_library_path "$<TARGET_FILE:Shaderc::shaderc_shared>")
	endif()
	if(NOT _shaderc_include_dir)
		message(FATAL_ERROR "CustomDeps could not determine SHADERC_INCLUDE_DIR.")
	endif()

	set(${out_include_dir} "${_shaderc_include_dir}" PARENT_SCOPE)
	set(${out_library_path} "${_shaderc_library_path}" PARENT_SCOPE)
endfunction()

function(pcsx2_resolve_custom_deps)
	pcsx2_resolve_custom_dep_plutovg()
	pcsx2_resolve_custom_dep_plutosvg()

	if(USE_VULKAN)
		pcsx2_resolve_custom_dep_shaderc(_pcsx2_shaderc_include_dir _pcsx2_shaderc_library_path)
		set(SHADERC_INCLUDE_DIR "${_pcsx2_shaderc_include_dir}" PARENT_SCOPE)
		set(SHADERC_LIBRARY "${_pcsx2_shaderc_library_path}" PARENT_SCOPE)
	endif()

	if(ENABLE_QT_UI)
		pcsx2_resolve_custom_dep_kddockwidgets()
	endif()
endfunction()
