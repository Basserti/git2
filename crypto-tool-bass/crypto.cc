#include "ctb-container.h"
#include "ctb-utils.h"
#include <iostream>

namespace ctb
{
namespace utils
{
	void generate_crc32_lut(uint32_t * table)
	{
		std::cout << "Start generate_crc32_lut" << std::endl;
		using ctb::container::CRC32_POLY;
		for (int i = 0; i < 256; i++)
		{
			uint32_t b = i;
			for (unsigned j = 0; j < 8; j++)
			{
				if 	(b & 1) b = (b >> 1) ^ CRC32_POLY;
				else 		b = (b >> 1);
				std::cout << i << " " << j << std::endl;
			}
			table[i] = b;
		}
		std::cout << "Finish generate_crc32_lut" << std::endl;
	}

	uint32_t update_crc32(uint32_t * table, uint8_t b, uint32_t crc)
	{
		uint32_t result = crc;
		result = table[(crc ^ b) & 0xff];
		return result;
	}
}
}

