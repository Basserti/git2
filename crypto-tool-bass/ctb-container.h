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
	RAW = 0,			// "—ырые" данные
	KEY_DATA,			//  люч дл€ сим шифра
	ENCRYPTED_DATA,		// Ўифротекст
	DH_PARAMS,			// TODO потом ????)
};

enum crypt_type
{
	RAW_CRYPT = 0,			// "—ырые" данные
	ECB_CRYPT,
	CBC_CRYPT,
	CTR_CRYPT
};


constexpr uint32_t HEADER_SIZE = 12;
constexpr uint32_t FILE_METADATA_SIZE = 24;

#pragma pack(push,1)

struct header
{
	uint32_t magic;
	uint32_t header_size;

	uint8_t payload;
	uint8_t crypt;
	uint8_t padding[2];
	// 12 byte

};

struct metadata
{
	uint32_t length;

	union
	{
			struct
			{
				uint64_t orig_length; // 16 byte
				uint64_t block_count; // 16 byte
				uint32_t block_size;  // 8 byte
				// 24 byte
			} file;
			struct {
				uint64_t orig_length; // 16 byte
				uint64_t block_count; // 16 byte
				uint32_t block_size;  // 8 byte
				// 24 byte
			} key;
	};

};

#pragma pack(pop)

}

}




#endif /* CTB_CONTAINER_H_ */
