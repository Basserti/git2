/*
 * ctb-hash.h
 *
 *  Created on: 3 но€б. 2021 г.
 *      Author: Lev
 */

#ifndef CTB_HASH_H_
#define CTB_HASH_H_

#include <cstdint>

namespace ctb
{
namespace hash
{
void gost_34_11_hash_256(uint8_t message);
void gost_34_11_hash_512();
}
}


#endif /* CTB_HASH_H_ */
