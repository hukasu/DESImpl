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
		NAME des_test_vector_1_1
		COMMAND des_test_runner
			"40000000000000000000000000000000"
			"0000000000000000"
			"60CC37B7B537A1DC"
	)
	add_test(
		NAME des_test_vector_1_2
		COMMAND des_test_runner
			"20000000000000000000000000000000"
			"0000000000000000"
			"BE3E7304FE92C2BC"
	)
	
	add_test(
		NAME des_test_vector_2_0
		COMMAND des_test_runner
			"00000000000000000000000000000000"
			"8000000000000000"
			"95F8A5E5DD31D900"
	)
	add_test(
		NAME des_test_vector_2_1
		COMMAND des_test_runner
			"00000000000000000000000000000000"
			"4000000000000000"
			"DD7F121CA5015619"
	)
	add_test(
		NAME des_test_vector_2_2
		COMMAND des_test_runner
			"00000000000000000000000000000000"
			"2000000000000000"
			"2E8653104F3834EA"
	)
	
	add_test(
		NAME des_test_vector_3_0
		COMMAND des_test_runner
			"00000000000000000000000000000000"
			"0000000000000000"
			"8CA64DE9C1B123A7"
	)
	add_test(
		NAME des_test_vector_3_1
		COMMAND des_test_runner
			"01010101010101010101010101010101"
			"0101010101010101"
			"994D4DC157B96C52"
	)
	add_test(
		NAME des_test_vector_3_2
		COMMAND des_test_runner
			"02020202020202020202020202020202"
			"0202020202020202"
			"E127C2B61D98E6E2"
	)

	add_test(
		NAME des_test_vector_4_0
		COMMAND des_test_runner
			"000102030405060708090A0B0C0D0E0F"
			"0011223344556677"
			"D117BD6373549FAA"
	)
	add_test(
		NAME des_test_vector_4_1
		COMMAND des_test_runner
			"2BD6459F82C5B300952C49104881FF48"
			"EA024714AD5C4D84"
			"C616ACE843958247"
	)
	
	add_test(
		NAME des_test_vector_5_0
		COMMAND des_test_runner
			"80000000000000000000000000000000"
			"DA57FF9FEB5B0FD8"
			"0000000000000000"
	)
	add_test(
		NAME des_test_vector_5_1
		COMMAND des_test_runner
			"40000000000000000000000000000000"
			"5795D061F2419F90"
			"0000000000000000"
	)

	add_test(
		NAME des_test_vector_5_2
		COMMAND des_test_runner
			"20000000000000000000000000000000"
			"9D066810D8D6D84D"
			"0000000000000000"
	)
endif()