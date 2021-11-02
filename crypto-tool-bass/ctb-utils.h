#ifndef CTB_UTILS_H_
#define CTB_UTILS_H_

#include <cstdint>

namespace ctb
{
namespace utils
{
	void generate_crc32_lut(uint32_t * table);
	uint32_t update_crc32(uint32_t * table, uint8_t b, uint32_t crc);
}
}




#endif /* CTB_UTILS_H_ */
