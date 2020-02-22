#ifndef __DES__LIB__HPP__
#define __DES__LIB__HPP__

#include <sstream>

namespace des {
	void encrypt(std::istream& _input_data, std::ostream& _output_cypher, std::istream& _key);
	void decrypt(std::istream& _input_cypher, std::ostream& _output_data, std::istream& _key);
}

#endif // __DES__LIB__HPP__