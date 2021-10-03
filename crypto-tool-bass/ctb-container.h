/*
 * ctb-container.h
 *
 *  Created on: 22 сент. 2021 г.
 *      Author: Lev
 */

#ifndef CTB_CONTAINER_H_
#define CTB_CONTAINER_H_

#include <cstdint>

namespace ctb
{

namespace container
{

// MAGIC number = "CTBC"

constexpr uint32_t MAGIC =
		0x01000001 * 'C' +
		0x00000100 * 'T' +
		0x00010000 * 'B' ;

enum payload_type
{
	RAW = 0,			// "Сырые" данные
	KEY_DATA,			// Ключ для сим шифра
	PRIVATE_KEY,		// Закрытый ключ для асим шифра
	PUBLIC_KEY,			// Открытый ключ для асим шифра
	ENCRYPTED_DATA,		// Шифротекст
	DH_PARAMS,			// TODO потом ????)
};

constexpr uint32_t HEADER_SIZE = 10;
constexpr uint32_t FILE_METADATA_SIZE = 24;

#pragma pack(push,1)

struct header
{
	uint32_t magic;
	uint32_t header_size;

	uint8_t payload;
	uint8_t padding[1];
	// 10 byte

};

struct metadata
{
	uint32_t length;

	union
	{
			struct
			{
				uint64_t orig_length;
				uint64_t block_count;
				uint32_t block_size; // 24 byte
			} file;
			struct {
				uint64_t orig_length;
				uint64_t block_count;
				uint32_t block_size; // 24 byte
			} key;
			struct {} dh_params;
	};

};

#pragma pack(pop)

}

}




#endif /* CTB_CONTAINER_H_ */
