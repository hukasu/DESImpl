#include <deslib.hpp>
#include <iostream>
#include <iomanip>

std::string fromHexStringToBits(std::string _input) {
	std::stringstream input_ss(std::ios::in | std::ios::out | std::ios::binary), output_ss(std::ios::in | std::ios::out | std::ios::binary);
	input_ss << _input;
	char hex[2];
	while (!input_ss.read(hex, 2).eof()) {
		size_t l;
		char c = static_cast<char>(std::stoi(hex, &l, 16));
		if (l != 2) throw std::runtime_error("Converter encountered a invalid hex value.");
		else output_ss << static_cast<char>(std::stoi(hex, nullptr, 16));
	}
	return output_ss.str();
}

std::string fromBitsToHexString(std::string _input) {
	std::stringstream input_ss(std::ios::in | std::ios::out | std::ios::binary), output_ss(std::ios::in | std::ios::out | std::ios::binary);
	input_ss << _input;
	char hex[2];
	hex[1] = '\x0';
	while (!input_ss.read(hex, 1).eof()) {
		output_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint64_t>(hex[0]);
	}
	return output_ss.str();
}

int main(int argc, char** argv) {
	if (argc != 4) {
		std::cout << argv[0] << " <key> <plain> <chypher>" << std::endl;
		return -1;
	}

	std::string
		data(fromHexStringToBits(std::string(argv[2]))),
		result(fromHexStringToBits(std::string(argv[3]))),
		key(fromHexStringToBits(std::string(argv[1])));

	std::istringstream data_stream(data, std::ios::in | std::ios::binary);
	std::ostringstream cypher_stream(std::ios::out | std::ios::binary);
	std::istringstream key_stream(key, std::ios::in | std::ios::binary);

	des::encrypt(data_stream, cypher_stream, key_stream);

	std::string cypher = cypher_stream.str();

	if (cypher.compare(result)) return -1;

	std::istringstream inv_data_stream(cypher, std::ios::in | std::ios::binary);
	std::ostringstream inv_cypher_stream(std::ios::out | std::ios::binary);

	des::decrypt(inv_data_stream, inv_cypher_stream, key_stream);

	std::string inv_cypher = inv_cypher_stream.str();

	if (inv_cypher.compare(data)) return -1;

	return 0;
}