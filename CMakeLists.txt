cmake_minimum_required(VERSION 3.8.2)

project(DESImpl)

add_library(
	DESImplLib
	STATIC
	src/deslib.cpp
)
target_compile_features(
	DESImplLib
	PUBLIC cxx_std_14
)