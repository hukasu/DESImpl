cmake_minimum_required(VERSION 3.8.2)

project(DESImpl)

option(BUILD_TESTS "Build tests?" OFF)

add_library(
	DESImplLib
	STATIC
	src/deslib.cpp
)
target_include_directories(
	DESImplLib
	INTERFACE src
)
target_compile_features(
	DESImplLib
	PUBLIC cxx_std_14
)

if (BUILD_TESTS)
	enable_testing()
	add_executable(
		des_test_runner
		test/des_test_runner.cpp
	)
	target_link_libraries(
		des_test_runner
		PUBLIC DESImplLib
	)

	add_test(
		NAME des_test_vector_1_0
		COMMAND des_test_runner
			"80000000000000000000000000000000"
			"0000000000000000"
			"FAFD5084374FCE34"
	)

	add_test(
		NAME des_test_vector_4_0
		COMMAND des_test_runner
			"000102030405060708090A0B0C0D0E0F"
			"0011223344556677"
			"D117BD6373549FAA"
	)
endif()