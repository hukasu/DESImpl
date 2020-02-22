#include "deslib.hpp"

#include <array>
#include <sstream>

namespace des {
	uint64_t readLong(std::istream& _stream);
	void writeLong(std::ostream& _stream, uint64_t _value);
	void permute(uint64_t& _block);
	void inversePermute(uint64_t& _block);
	void roundCompute(uint32_t& _l_block, uint32_t& _r_block, uint64_t _scheduled_key);
	uint32_t roundFunction(uint32_t _block, uint64_t _scheduled_key);
	uint64_t eBitSelection(uint32_t _block);
	uint8_t sBitSelection(uint8_t _iteration, uint8_t _block);
	uint32_t roundPermute(uint32_t _block);
	std::array<uint64_t, 16> keySchedule(uint64_t _key);
	uint64_t keySchedulePermute1(uint64_t _key);
	uint64_t keySchedulePermute2(uint64_t _key);
	uint8_t keyScheduleShift(uint8_t _iteration);
	std::array<uint64_t, 3> readKeys(std::istream& _key_stream);

	void _encrypt(std::istream& _input_data, std::ostream& _output_cypher, uint64_t _key);
	void _decrypt(std::istream& _input_cypher, std::ostream& _output_data, uint64_t _key);

	static std::array<uint8_t, 64> permutation_table {
		58, 50, 42, 34, 26, 18, 10,  2,
		60, 52, 44, 36, 28, 20, 12,  4,
		62, 54, 46, 38, 30, 22, 14,  6,
		64, 56, 48, 40, 32, 24, 16,  8,
		57, 49, 41, 33, 25, 17,  9,  1,
		59, 51, 43, 35, 27, 19, 11,  3,
		61, 53, 45, 37, 29, 21, 13,  5,
		63, 55, 47, 39, 31, 23, 15,  7
	};

	static std::array<uint8_t, 64> inverse_permutation_table {
		40,  8, 48, 16, 56, 24, 64, 32,
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25
	};

	static std::array<uint8_t, 64> e_bit_selection_table {
		32,  1,  2,  3,  4,  5,
		 4,  5,  6,  7,  8,  9,
		 8,  9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32,  1
	};

	static std::array<std::array<std::array<uint8_t, 16>, 4>, 8> s_bit_selection {
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				14,  4, 13,  1,  2, 15, 11,  8,
				 3, 10,  6, 12,  5,  9,  0,  7
			},
			std::array<uint8_t, 16> {
				 0, 15,  7,  4, 14,  2, 13,  1,
				10,  6, 12, 11,  9,  5,  3,  8
			},
			std::array<uint8_t, 16> {
				 4,  1, 14,  8, 13,  6,  2, 11,
				15, 12,  9,  7,  3, 10,  5,  0
			},
			std::array<uint8_t, 16> {
				15, 12,  8,  2,  4,  9,  1,  7,
				 5, 11,  3, 14, 10,  0,  6, 13
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				15,  1,  8, 14,  6, 11,  3,  4,
				 9,  7,  2, 13, 12,  0,  5, 10
			},
			std::array<uint8_t, 16> {
				 3, 13,  4,  7, 15,  2,  8, 14,
				12,  0,  1, 10,  6,  9, 11,  5
			},
			std::array<uint8_t, 16> {
				 0, 14,  7, 11, 10,  4, 13,  1,
				 5,  8, 12,  6,  9,  3,  2, 15
			},
			std::array<uint8_t, 16> {
				13,  8, 10,  1,  3, 15,  4,  2,
				11,  6,  7, 12,  0,  5, 14,  9
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				10,  0,  9, 14,  6,  3, 15,  5,
				 1, 13, 12,  7, 11,  4,  2,  8
			},
			std::array<uint8_t, 16> {
				13,  7,  0,  9,  3,  4,  6, 10,
				 2,  8,  5, 14, 12, 11, 15,  1
			},
			std::array<uint8_t, 16> {
				13,  6,  4,  9,  8, 15,  3,  0,
				11,  1,  2, 12,  5, 10, 14,  7
			},
			std::array<uint8_t, 16> {
				 1, 10, 13,  0,  6,  9,  8,  7,
				 4, 15, 14,  3, 11,  5,  2, 12
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				 7, 13, 14,  3,  0,  6,  9, 10,
				 1,  2,  8,  5, 11, 12,  4, 15
			},
			std::array<uint8_t, 16> {
				13,  8, 11,  5,  6, 15,  0,  3,
				 4,  7,  2, 12,  1, 10, 14,  9
			},
			std::array<uint8_t, 16> {
				10,  6,  9,  0, 12, 11,  7, 13,
				15,  1,  3, 14,  5,  2,  8,  4
			},
			std::array<uint8_t, 16> {
				 3, 15,  0,  6, 10,  1, 13,  8,
				 9,  4,  5, 11, 12,  7,  2, 14
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				 2, 12,  4,  1,  7, 10, 11,  6,
				 8,  5,  3, 15, 13,  0, 14,  9
			},
			std::array<uint8_t, 16> {
				14, 11,  2, 12,  4,  7, 13,  1,
				 5,  0, 15, 10,  3,  9,  8,  6
			},
			std::array<uint8_t, 16> {
				 4,  2,  1, 11, 10, 13,  7,  8,
				15 , 9, 12,  5,  6,  3,  0, 14
			},
			std::array<uint8_t, 16> {
				11,  8, 12,  7,  1, 14,  2, 13,
				 6, 15,  0,  9, 10,  4,  5,  3
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				12,  1, 10, 15,  9,  2,  6,  8,
				 0, 13,  3,  4, 14,  7,  5, 11
			},
			std::array<uint8_t, 16> {
				10, 15,  4,  2,  7, 12,  9,  5,
				 6,  1, 13, 14,  0, 11,  3,  8
			},
			std::array<uint8_t, 16> {
				 9, 14, 15,  5,  2,  8, 12,  3,
				 7,  0,  4, 10,  1, 13, 11,  6
			},
			std::array<uint8_t, 16> {
				 4,  3,  2, 12,  9,  5, 15, 10,
				11, 14,  1,  7,  6,  0,  8, 13
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				 4, 11,  2, 14, 15,  0,  8, 13,
				 3, 12,  9,  7,  5, 10,  6,  1
			},
			std::array<uint8_t, 16> {
				13,  0, 11,  7,  4,  9,  1,  10,
				14,  3,  5, 12,  2, 15,  8,  6
			},
			std::array<uint8_t, 16> {
				 1,  4, 11, 13, 12,  3,  7, 14,
				10, 15,  6,  8,  0,  5,  9,  2
			},
			std::array<uint8_t, 16> {
				 6, 11, 13,  8,  1,  4, 10,  7,
				 9,  5,  0, 15, 14,  2,  3, 12
			}
		},
		std::array<std::array<uint8_t, 16>, 4> {
			std::array<uint8_t, 16> {
				13,  2,  8,  4,  6, 15, 11,  1,
				10,  9,  3, 14,  5,  0, 12,  7
			},
			std::array<uint8_t, 16> {
				 1, 15, 13,  8, 10,  3,  7,  4,
				12,  5,  6, 11,  0, 14,  9,  2
			},
			std::array<uint8_t, 16> {
				 7, 11,  4,  1,  9, 12, 14,  2,
				 0,  6, 10, 13, 15,  3,  5,  8
			},
			std::array<uint8_t, 16> {
				 2,  1, 14,  7,  4, 10,  8, 13,
				15, 12,  9,  0,  3,  5,  6, 11
			}
		},
	};

	static std::array<uint8_t, 32> round_permutation_table {
		16,  7, 20, 21, 29, 12, 28, 17,
		 1, 15, 23, 26,  5, 18, 31, 10,
		 2,  8, 24, 14, 32, 27,  3,  9,
		19, 13, 30,  6, 22, 11,  4, 25
	};

	static std::array<uint8_t, 56> key_permutation_table_1 {
		57, 49, 41, 33, 25, 17,  9,
		 1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		 7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4
	};

	static std::array<uint8_t, 48> key_permutation_table_2 {
		14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};

	/** Read Long */
	uint64_t readLong(std::istream& _stream) {
		uint64_t k = 0;
		std::array<uint8_t, 8> data;
		_stream.read(reinterpret_cast<char*>(data.data()), 8);
		for (uint8_t i = 0; i < 8; i++) {
			k <<= 8;
			k |= data[i];
		}
		return k;
	}

	void writeLong(std::ostream& _stream, uint64_t _value) {
		std::array<uint8_t, 8> data;
		for (uint8_t i = 0; i < 8; i++) {
			data[7 - i] = static_cast<uint8_t>(_value & 0xff);
			_value >>= 8;
		}
		_stream.write(reinterpret_cast<char*>(data.data()), 8);
	}

	/** Bit permutation */
	void permute(uint64_t& _block) {
		uint64_t copy = _block;
		_block = 0;
		for (uint8_t i = 0; i < 64; i++) {
			_block <<= 1;
			_block |= (copy >> (64 - permutation_table[i])) & 0b1;
		}
	}

	/** Inverse Bit permutation */
	void inversePermute(uint64_t& _block) {
		uint64_t copy = _block;
		_block = 0;
		for (uint8_t i = 0; i < 64; i++) {
			_block <<= 1;
			_block |= (copy >> (64 - inverse_permutation_table[i])) & 0b1;
		}
	}

	/** Round computation */
	void roundCompute(uint32_t& _l_block, uint32_t& _r_block, uint64_t _scheduled_key) {
		uint32_t l_block_copy = _l_block;
		_l_block = _r_block; // L' = R
		_r_block = l_block_copy ^ roundFunction(_r_block, _scheduled_key); // R' = L XOR f(R, K)
	}

	/** Round function */
	uint32_t roundFunction(uint32_t _block, uint64_t _scheduled_key) {
		uint64_t e_block = eBitSelection(_block); // E(R)
		uint64_t ekn_block = _scheduled_key ^ e_block; // B1B2...B8 = K XOR E(R)
		uint32_t s_block = 0;
		for (uint8_t i = 0; i < 8; i++) {
			s_block <<= 4;
			uint8_t b_block = ((ekn_block >> (48 - ((i + 1) * 6))) & 0x3f);
			s_block |= sBitSelection(i, b_block); // Si(Bi)
		}
		uint32_t p_block = roundPermute(s_block); // P(S1(B1)S2(B2)...S8(B8))
		return p_block;
	}

	/** E-Bit Selection
	* Result is 48-bit wide.
	*/
	uint64_t eBitSelection(uint32_t _block) {
		uint64_t res_block = 0;
		for (uint8_t i = 0; i < 48; i++) {
			res_block <<= 1;
			res_block |= (_block >> (32 - e_bit_selection_table[i])) & 0b1;
		}
		return res_block;
	}

	/** S-Bit Selection
	* Block is 6-bit wide, and result is 4-bit wide.
	*/
	uint8_t sBitSelection(uint8_t _iteration, uint8_t _block) {
		uint8_t i = (((_block & 0b100000) >> 4) | (_block & 0b1));
		uint8_t j = ((_block & 0b11110) >> 1);
		return s_bit_selection[_iteration][i][j];
	}

	/** Bit permutation */
	uint32_t roundPermute(uint32_t _block) {
		uint32_t res_block = 0;
		for (uint8_t i = 0; i < 32; i++) {
			res_block <<= 1;
			res_block |= (_block >> (32 - round_permutation_table[i])) & 0b1;
		}
		return res_block;
	}

	/** Key Scheduling
	* Result is 16 48-bit wide key blocks
	*/
	std::array<uint64_t, 16> keySchedule(uint64_t _key) {
		std::array<uint64_t, 16> scheduled_key;
		uint64_t key_block = keySchedulePermute1(_key);
		for (uint8_t i = 0; i < 16; i++) {
			if (keyScheduleShift(i) == 1) {
				key_block <<= 1;
				uint64_t round = (key_block & 0x0100000010000000);
				key_block = (key_block & (~0x0100000010000000)) | (round >> 28);
			} else {
				key_block <<= 2;
				uint64_t round = (key_block & 0x0300000030000000);
				key_block = (key_block & (~0x0300000030000000)) | (round >> 28);
			}
			scheduled_key[i] = keySchedulePermute2(key_block);
		}
		return std::move(scheduled_key);
	}

	/** Key Scheduling Permute 1 */
	uint64_t keySchedulePermute1(uint64_t _key) {
		uint64_t res_block = 0;
		for (uint8_t i = 0; i < 56; i++) {
			res_block <<= 1;
			res_block |= (_key >> (64 - key_permutation_table_1[i])) & 0b1;
		}
		return res_block;
	}

	/** Key Scheduling Permute 2 */
	uint64_t keySchedulePermute2(uint64_t _key) {
		uint64_t res_block = 0;
		for (uint8_t i = 0; i < 48; i++) {
			res_block <<= 1;
			res_block |= (_key >> (56 - key_permutation_table_2[i])) & 0b1;
		}
		return res_block;
	}

	/** Key Scheduling Shift */
	uint8_t keyScheduleShift(uint8_t _iteration) {
		if (_iteration == 0 || _iteration == 1 || _iteration == 8 || _iteration == 15) return 1;
		else return 2;
	}

	std::array<uint64_t, 3> readKeys(std::istream& _key_stream) {
		std::array<uint64_t, 3> keys;
		_key_stream.seekg(0, std::ios::end);
		size_t key_size = _key_stream.tellg();
		_key_stream.seekg(0, std::ios::beg);
		if (key_size % 8) throw std::runtime_error("Key does not have size multiple of 64 bits.");
		if (key_size > 24) throw std::runtime_error("Operation with more than 3 keys is undefined. Use up to 3 keys (64, 128, 196 bits).");
		uint8_t key_count = static_cast<uint8_t>(key_size) / 8;

		uint64_t k;
		if (key_count == 1) {
			k = readLong(_key_stream);
			keys[0] = k;
			keys[1] = k;
			keys[2] = k;
		} else if (key_count == 2) {
			k = readLong(_key_stream);
			keys[0] = k;
			keys[2] = k;
			k = readLong(_key_stream);
			keys[1] = k;
		} else if (key_count == 3) {
			k = readLong(_key_stream);
			keys[0] = k;
			k = readLong(_key_stream);
			keys[1] = k;
			k = readLong(_key_stream);
			keys[2] = k;
		}
		return std::move(keys);
	}

	void _encrypt(std::istream& _input_data, std::ostream& _output_cypher, uint64_t _key) {
		union {
			uint64_t w_block;
			struct {
				uint32_t r_block;
				uint32_t l_block;
			};
		};

		_input_data.seekg(0, std::ios::end);
		uint64_t data_length = _input_data.tellg();
		_input_data.seekg(0, std::ios::beg);

		std::array<uint64_t, 16> key_schedule = keySchedule(_key); // KS

		for (uint64_t i = 0; i < data_length; i += 8) {
			w_block = readLong(_input_data);
			permute(w_block); // IP
			for (uint8_t i = 0; i < 16; i++) {
				roundCompute(l_block, r_block, key_schedule[i]);
			}
			std::swap(l_block, r_block); // L16R16 -> R16L16
			inversePermute(w_block); // IP^-1
			writeLong(_output_cypher, w_block);
		}
		if (data_length % 8) {
			w_block = 0;
			_input_data.read(reinterpret_cast<char*>(&w_block), data_length % 8);
			permute(w_block); // IP
			for (uint8_t i = 0; i < 16; i++) {
				roundCompute(l_block, r_block, key_schedule[i]);
			}
			std::swap(l_block, r_block); // L16R16 -> R16L16
			inversePermute(w_block); // IP^-1
			writeLong(_output_cypher, w_block);
		}
	}

	void _decrypt(std::istream& _input_cypher, std::ostream& _output_data, uint64_t _key) {
		union {
			uint64_t w_block;
			struct {
				uint32_t r_block;
				uint32_t l_block;
			};
		};

		_input_cypher.seekg(0, std::ios::end);
		uint64_t data_length = _input_cypher.tellg();
		_input_cypher.seekg(0, std::ios::beg);

		std::array<uint64_t, 16> key_schedule = keySchedule(_key); // KS

		for (uint64_t i = 0; i < data_length; i += 8) {
			w_block = readLong(_input_cypher);
			permute(w_block); // IP
			for (uint8_t i = 0; i < 16; i++) {
				roundCompute(l_block, r_block, key_schedule[15 - i]);
			}
			std::swap(l_block, r_block); // L16R16 -> R16L16
			inversePermute(w_block); // IP^-1
			writeLong(_output_data, w_block);
		}
	}

	void encrypt(std::istream& _input_data, std::ostream& _output_cypher, std::istream& _key_stream) {
		std::array<uint64_t, 3> keys = readKeys(_key_stream);

		// Triple DES Pass 1
		std::stringstream pass1_output(std::ios::binary | std::ios::in | std::ios::out);
		_encrypt(_input_data, pass1_output, keys[0]);

		// Triple DES Pass 2
		std::stringstream pass2_output(std::ios::binary | std::ios::in | std::ios::out);
		_decrypt(pass1_output, pass2_output, keys[1]);

		// Triple DES Pass 3
		_encrypt(pass2_output, _output_cypher, keys[2]);
	}

	void decrypt(std::istream& _input_cypher, std::ostream& _output_data, std::istream& _key_stream) {
		std::array<uint64_t, 3> keys = readKeys(_key_stream);

		// Triple DES Pass 1
		std::stringstream pass1_output(std::ios::binary | std::ios::in | std::ios::out);
		_decrypt(_input_cypher, pass1_output, keys[2]);

		// Triple DES Pass 2
		std::stringstream pass2_output(std::ios::binary | std::ios::in | std::ios::out);
		_encrypt(pass1_output, pass2_output, keys[1]);

		// Triple DES Pass 3
		_decrypt(pass2_output, _output_data, keys[0]);
	}
}