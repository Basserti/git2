#include <iostream>
#include <fstream>
#include <cstring>
#include <stdint.h>
#include <cstdlib>
#include <random>
#include <algorithm>

//#include <ctb-container.h>

#include "ctb-container.h"
#include "ctb-utils.h"
#include "ctb-hash.h"

const uint8_t message[72] {
		0xfb,0xe2,0xe5,0xf0,0xee,0xe3,0xc8,0x20,0xfb,0xea,
		0xfa,0xeb,0xef,0x20,0xff,0xfb,0xf0,0xe1,0xe0,0xf0,
		0xf5,0x20,0xe0,0xed,0x20,0xe8,0xec,0xe0,0xeb,0xe5,
		0xf0,0xf2,0xf1,0x20,0xff,0xf0,0xee,0xec,0x20,0xf1,
		0x20,0xfa,0xf2,0xfe,0xe5,0xe2,0x20,0x2c,0xe8,0xf6,
		0xf3,0xed,0xe2,0x20,0xe8,0xe6,0xee,0xe1,0xe8,0xf0,
		0xf2,0xd1,0x20,0x2c,0xe8,0xf0,0xf2,0xe5,0xe2,0x20,
		0xe5,0xd1
};

const uint32_t BLOCK_SIZE = 32;
const char * CRYPT_NAME[4] = {"RAW_", "ECB_", "CBC_", "CTR_"};
const char * IV = "dota";
const uint32_t T_SWAP[16] = {3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14};
//                           0  1  2  3  4  5   6   7   8  9  10  11 12 13 14  15

void network_feistel(uint16_t &Li,uint16_t &Ri,uint8_t key[], bool crypt)
{
	for(uint16_t step = 0; step < 8; step++)
	{

		uint16_t a[4] {};
		uint32_t y = 0;
		for(uint32_t i = 0; i < 16; i=i+4)
		{
			a[y] = (((Li >> (i+3)) & 1) << 0) | (((Li >> (i+2)) & 1) << 1) | (((Li >> (i+1)) & 1) << 2) | (((Li >> i) & 1) << 3);
			y += 1;
		}

		uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8) | (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

		uint16_t key_buff;
		if (crypt == true)
			key_buff = (key[step * 2] << 8) + key[step * 2 + 1];
		else
			key_buff = (key[15 - (step * 2 + 1)] << 8) + key[15 - (step * 2)];

		Sx ^= key_buff;

		Sx = (Sx << 3) | (Sx >> (16-3));

		uint16_t oldLi = Li;
		Li = Ri ^ Sx;
		Ri = oldLi;
		//std::cout << Li << " " << Ri << std::endl;
	}

	std::swap (Li, Ri);
}


void increment_block(uint8_t * block, size_t sz)
{
	unsigned current_byte = 0;
	while (current_byte < sz)
	{
		uint8_t old_value = block[current_byte];
		uint8_t new_value = old_value + 1;
		block[current_byte] = new_value;
		if (new_value > old_value) return;
		current_byte++;
	}
}

void create_container(std::string name_file)
{

	int choose_crypto;
	std::string name_key_cont_file;
	//for(;;)
	{
		std::cout << "Choose the type of encryption:\n"
				<< "1. RAW\n"
				<< "2. ECB\n"
				<< "3. CBC\n"
				<< "4. CTR"
				<< std::endl;
		std::cin >> choose_crypto;
		choose_crypto -= 1;
		switch(choose_crypto)
		{
			case 0:
			{
				std::cout << "Selected RAW encryption" << std::endl;
				break;
			}
			case 1:
			case 2:
			case 3:
			{
				std::cout << "Enter KEY container name:" << std::endl;
				//name_key_cont_file = "1-key_cont.ctb"; // DEBAG
				std::cin >> name_key_cont_file;
				std::cout <<"Key: " << name_key_cont_file << std::endl;
				break;
			}
		}
	}

	std::ifstream src_file;
	src_file.open(name_file.c_str(), std::ios::binary | std::ios::ate);

	if(!src_file.is_open())
	{
		std::cerr <<
				"File dont open!"
				<< std::endl;
		return;
	}


	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	std::cout << "Start create encryption container" << std::endl;

	std::ofstream dst_file;
	std::string container_name_file = CRYPT_NAME[choose_crypto] + name_file + "-container.ctb";
	dst_file.open(container_name_file.c_str(), std::ios::binary);

	using namespace ctb::container;

	header hdr{};
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = ENCRYPTED_DATA;
	hdr.crypt = choose_crypto;

	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);

	metadata md{};
	uint32_t name_length =strlen(name_file.c_str());
	md.length = FILE_METADATA_SIZE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = BLOCK_SIZE;
	md.file.block_count = filesize / (BLOCK_SIZE / 8);
	if (filesize % (BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	auto file_header_pos = dst_file.tellp();
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE);
	dst_file.write(name_file.c_str(), name_length + 1);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];
	ctb::utils::generate_crc32_lut(crc32_table);

	uint32_t word_crypt = *((uint32_t*)IV);

	for (uint64_t block = 0; block < md.file.block_count; block++)
	{
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);

		for (unsigned k = 0; k < BLOCK_SIZE /8; k++)
			crc32 = ctb::utils::update_crc32(crc32_table, buffer[k], crc32);

		switch(choose_crypto)
		{
			case 0:
				{
					dst_file.write(reinterpret_cast<char*>(&buffer[0]),
							BLOCK_SIZE / 8);
					break;
				}
			case 1:
				{
					std::ifstream src2_file;
					src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
					if(!src2_file.is_open())
					{
						std::cerr <<
								"File dont open!"
								<< std::endl;
						return;
					}
					using namespace ctb::container;
					header hdr2 {};
					src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
					if (hdr2.magic != MAGIC)
					{
						std::cerr <<
								"File dont open (MAGIC ERROR)!"
								<< std::endl;
						return;
					}
					if (hdr2.payload != KEY_DATA)
					{
						std::cerr <<
								"File no KEY_DATA data!"
								<< std::endl;
							return;
					}
					src2_file.seekg(hdr2.header_size);

					uint64_t pos_after_header2 = src2_file.tellg();

					metadata md2 {};
					src2_file.readsome(reinterpret_cast<char*>(&md2),
							FILE_METADATA_SIZE);
					src2_file.seekg(pos_after_header2 + md2.length);

					uint8_t key[16] = {};
					src2_file.read(reinterpret_cast<char*>(&key[0]),
							16);

					src2_file.close();
					//std::cout << "Key read OK!" << std::endl;

					uint16_t Li =  (buffer[3] << 8) + buffer[2];
					uint16_t Ri =  (buffer[1] << 8) + buffer[0];
					//std::cout << Li << " " << Ri << std::endl;
					network_feistel(Li, Ri, key, true);
					//std::cout << " " << std::endl;
					uint32_t cryptParts = (Li << 16) + Ri;

					dst_file.write(reinterpret_cast<char*>(&cryptParts),
							BLOCK_SIZE / 8);
					break;
				}
			case 2:
				{
					std::ifstream src2_file;
					src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
					if(!src2_file.is_open())
					{
						std::cerr <<
								"File dont open!"
								<< std::endl;
						return;
					}
					using namespace ctb::container;
					header hdr2 {};
					src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
					if (hdr2.magic != MAGIC)
					{
						std::cerr <<
								"File dont open (MAGIC ERROR)!"
								<< std::endl;
						return;
					}
					if (hdr2.payload != KEY_DATA)
					{
						std::cerr <<
								"File no KEY_DATA data!"
								<< std::endl;
							return;
					}
					src2_file.seekg(hdr2.header_size);

					uint64_t pos_after_header2 = src2_file.tellg();

					metadata md2 {};
					src2_file.readsome(reinterpret_cast<char*>(&md2),
							FILE_METADATA_SIZE);
					src2_file.seekg(pos_after_header2 + md2.length);

					uint8_t key[16] = {};
					src2_file.read(reinterpret_cast<char*>(&key[0]),
							16);

					src2_file.close();

					uint32_t word = (buffer[3] << 24) + (buffer[2] << 16)
							+ (buffer[1] << 8) + buffer[0];
					word ^= word_crypt;
					uint16_t Li =  word >> 16 & 0xFFFF;
					uint16_t Ri =  word & 0xFFFF;
					network_feistel(Li, Ri, key, true);
					word_crypt = (Li << 16) + Ri;
					dst_file.write(reinterpret_cast<char*>(&word_crypt),
												BLOCK_SIZE / 8);
					break;
				}
			case 3:
				{
					std::ifstream src2_file;
					src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
					if(!src2_file.is_open())
					{
						std::cerr <<
								"File dont open!"
								<< std::endl;
						return;
					}
					using namespace ctb::container;
					header hdr2 {};
					src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
					if (hdr2.magic != MAGIC)
					{
						std::cerr <<
								"File dont open (MAGIC ERROR)!"
								<< std::endl;
						return;
					}
					if (hdr2.payload != KEY_DATA)
					{
						std::cerr <<
								"File no KEY_DATA data!"
								<< std::endl;
							return;
					}
					src2_file.seekg(hdr2.header_size);

					uint64_t pos_after_header2 = src2_file.tellg();

					metadata md2 {};
					src2_file.readsome(reinterpret_cast<char*>(&md2),
							FILE_METADATA_SIZE);
					src2_file.seekg(pos_after_header2 + md2.length);

					uint8_t key[16] = {};
					src2_file.read(reinterpret_cast<char*>(&key[0]),
							16);

					src2_file.close();

					uint16_t Li =  word_crypt >> 16 & 0xFFFF;
					uint16_t Ri =  word_crypt & 0xFFFF;

					network_feistel(Li, Ri, key, true);

					uint32_t word = (buffer[3] << 24) + (buffer[2] << 16)
							+ (buffer[1] << 8) + buffer[0];
					word ^= ((Li << 16) + Ri);

					dst_file.write(reinterpret_cast<char*>(&word),
							BLOCK_SIZE / 8);

					uint8_t word_crypt_to_blocks[4] {};
					word_crypt_to_blocks[3] = word_crypt & 0xFF;
					word_crypt_to_blocks[2] = word_crypt >> 8 & 0xFF;
					word_crypt_to_blocks[1] = word_crypt >> 16 & 0xFF;
					word_crypt_to_blocks[0] = word_crypt >> 24 & 0xFF;
					increment_block(&word_crypt_to_blocks[0], BLOCK_SIZE);
					word_crypt = (word_crypt_to_blocks[3] << 24)
							+ (word_crypt_to_blocks[2] << 16)
							+ (word_crypt_to_blocks[1] << 8)
							+ word_crypt_to_blocks[0];

					break;
				}
		}
	}

	md.file.crc32 = crc32;
	dst_file.seekp(file_header_pos);
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE);

	src_file.close();
	dst_file.close();
	std::cout << "Create encryption container" << std::endl;

}

void extract_container(std::string name_file)
{
	std::ifstream src_file;
	src_file.open(name_file.c_str(), std::ios::binary);
	if(!src_file.is_open())
		{
			std::cerr <<
					"File dont open!"
					<< std::endl;
			return;
		}

	using namespace ctb::container;

	header hdr {};
	src_file.read(reinterpret_cast<char*>(&hdr),
			sizeof(header));
	if (hdr.magic != MAGIC) {
			std::cerr <<
					"File dont open!"
					<< std::endl;
			return;
		}

	if (hdr.payload != ENCRYPTED_DATA) {
		std::cerr <<
				"File no ENCRYPTED_DATA data!"
				<< std::endl;
		return;
	}

	int crypto_type = hdr.crypt;

	std::string name_key_cont_file;
	switch(crypto_type)
	{
		case 0:
		{
			std::cout << "RAW encryption" << std::endl;
			break;
		}
		case 1:
		{
			std::cout << "ECB encryption" << std::endl;
			std::cout << "Enter KEY container name:" << std::endl;
			//name_key_cont_file = "1-key_cont.ctb"; // DEBAG
			std::cin >> name_key_cont_file;
			std::cout <<"Key: " << name_key_cont_file << std::endl;
			break;
		}
		case 2:
		{
			std::cout << "CBC encryption" << std::endl;
			std::cout << "Enter KEY container name:" << std::endl;
			//name_key_cont_file = "1-key_cont.ctb"; // DEBAG
			std::cin >> name_key_cont_file;
			std::cout <<"Key: " << name_key_cont_file << std::endl;
			break;
		}
		case 3:
		{
			std::cout << "CTR encryption" << std::endl;
			std::cout << "Enter KEY container name:" << std::endl;
			//name_key_cont_file = "1-key_cont.ctb"; // DEBAG
			std::cin >> name_key_cont_file;
			std::cout <<"Key: " << name_key_cont_file << std::endl;
			break;
		}
	}

	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata md {};
	src_file.readsome(reinterpret_cast<char*>(&md),
			FILE_METADATA_SIZE);
	std::string orig_file_name = "EXTRACTED_";
	char c;
	while ((c = src_file.get()))
	{
		orig_file_name += c;
	}
	std::cout << "Start extract encryption container" << std::endl;
	std::ofstream dst_file;
	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];

	ctb::utils::generate_crc32_lut(crc32_table);


	uint32_t word_crypt = *((uint32_t*)IV);

	while(md.file.orig_length > 0)
		{
			uint8_t buffer[BLOCK_SIZE / 8] {};
			src_file.read(reinterpret_cast<char*>(&buffer[0]),
					BLOCK_SIZE / 8);

			for (unsigned k = 0; k < BLOCK_SIZE /8; k++)
						crc32 = ctb::utils::update_crc32(crc32_table, buffer[k], crc32);

			uint64_t bytes_to_write = std::min<unsigned long>(4UL, md.file.orig_length);

			switch(crypto_type)
			{
				case 0:
					{
						dst_file.write(reinterpret_cast<char*>(&buffer[0]),
								bytes_to_write);
						break;
					}
				case 1:
					{
						std::ifstream src2_file;
						src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
						if(!src2_file.is_open())
						{
							std::cerr <<
									"File dont open!"
									<< std::endl;
							return;
						}
						using namespace ctb::container;
						header hdr2 {};
						src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
						if (hdr2.magic != MAGIC)
						{
							std::cerr <<
									"File dont open (MAGIC ERROR)!"
									<< std::endl;
								return;
						}
						if (hdr2.payload != KEY_DATA)
						{
								std::cerr <<
									"File no KEY_DATA data!"
									<< std::endl;
								return;
						}
						src2_file.seekg(hdr2.header_size);

						uint64_t pos_after_header2 = src2_file.tellg();

						metadata md2 {};
						src2_file.readsome(reinterpret_cast<char*>(&md2),
								FILE_METADATA_SIZE);
						src2_file.seekg(pos_after_header2 + md2.length);

						uint8_t key[16] {};
						src2_file.read(reinterpret_cast<char*>(&key[0]),
									16);

						src2_file.close();
						//std::cout << "Key read OK!" << std::endl;

						uint16_t Li =  (buffer[3] << 8) + buffer[2];
						uint16_t Ri =  (buffer[1] << 8) + buffer[0];
						//std::cout << Li << " " << Ri << std::endl;
						network_feistel(Li, Ri, key, false);
						//std::cout << " " << std::endl;

						uint32_t cryptParts = (Li << 16) + Ri;
						dst_file.write(reinterpret_cast<char*>(&cryptParts),
								bytes_to_write);
						break;
					}
				case 2:
					{
						std::ifstream src2_file;
						src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
						if(!src2_file.is_open())
						{
							std::cerr <<
									"File dont open!"
									<< std::endl;
							return;
						}
						using namespace ctb::container;
						header hdr2 {};
						src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
						if (hdr2.magic != MAGIC)
						{
							std::cerr <<
									"File dont open (MAGIC ERROR)!"
									<< std::endl;
								return;
						}
						if (hdr2.payload != KEY_DATA)
						{
								std::cerr <<
									"File no KEY_DATA data!"
									<< std::endl;
								return;
						}
						src2_file.seekg(hdr2.header_size);

						uint64_t pos_after_header2 = src2_file.tellg();

						metadata md2 {};
						src2_file.readsome(reinterpret_cast<char*>(&md2),
								FILE_METADATA_SIZE);
						src2_file.seekg(pos_after_header2 + md2.length);

						uint8_t key[16] {};
						src2_file.read(reinterpret_cast<char*>(&key[0]),
									16);

						src2_file.close();
						//std::cout << "Key read OK!" << std::endl;

						uint16_t Li =  (buffer[3] << 8) + buffer[2];
						uint16_t Ri =  (buffer[1] << 8) + buffer[0];
						uint32_t LiRi = (Li << 16) + Ri;
						network_feistel(Li, Ri, key, false);
						uint32_t word = (Li << 16) + Ri;
						word ^= word_crypt;
						word_crypt = LiRi;
						dst_file.write(reinterpret_cast<char*>(&word),
													BLOCK_SIZE / 8);
						break;
					}
				case 3:
					{
						std::ifstream src2_file;
						src2_file.open(name_key_cont_file.c_str(), std::ios::binary);
						if(!src2_file.is_open())
						{
							std::cerr <<
									"File dont open!"
									<< std::endl;
							return;
						}
						using namespace ctb::container;
						header hdr2 {};
						src2_file.read(reinterpret_cast<char*>(&hdr2),
								sizeof(header));
						if (hdr2.magic != MAGIC)
						{
							std::cerr <<
									"File dont open (MAGIC ERROR)!"
									<< std::endl;
								return;
						}
						if (hdr2.payload != KEY_DATA)
						{
								std::cerr <<
									"File no KEY_DATA data!"
									<< std::endl;
								return;
						}
						src2_file.seekg(hdr2.header_size);

						uint64_t pos_after_header2 = src2_file.tellg();

						metadata md2 {};
						src2_file.readsome(reinterpret_cast<char*>(&md2),
								FILE_METADATA_SIZE);
						src2_file.seekg(pos_after_header2 + md2.length);

						uint8_t key[16] {};
						src2_file.read(reinterpret_cast<char*>(&key[0]),
									16);

						src2_file.close();
						//std::cout << "Key read OK!" << std::endl;

						uint16_t Li =  word_crypt >> 16 & 0xFFFF;
						uint16_t Ri =  word_crypt & 0xFFFF;

						network_feistel(Li, Ri, key, true);

						uint32_t word = (buffer[3] << 24) + (buffer[2] << 16)
								+ (buffer[1] << 8) + buffer[0];
						word ^= ((Li << 16) + Ri);

						dst_file.write(reinterpret_cast<char*>(&word),
								BLOCK_SIZE / 8);

						uint8_t word_crypt_to_blocks[4] {};
						word_crypt_to_blocks[3] = word_crypt & 0xFF;
						word_crypt_to_blocks[2] = word_crypt >> 8 & 0xFF;
						word_crypt_to_blocks[1] = word_crypt >> 16 & 0xFF;
						word_crypt_to_blocks[0] = word_crypt >> 24 & 0xFF;
						increment_block(&word_crypt_to_blocks[0], BLOCK_SIZE);
						word_crypt = (word_crypt_to_blocks[3] << 24)
								+ (word_crypt_to_blocks[2] << 16)
								+ (word_crypt_to_blocks[1] << 8)
								+ word_crypt_to_blocks[0];

						break;
					}
			}
			md.file.orig_length -= bytes_to_write;
		}

	dst_file.close();
	src_file.close();

	if (crc32 !=md.file.crc32)
		std::cout << "WARNING! CRC MISMATCH!" << std::endl;

	std::cout << "Extract container" << std::endl;
}

void key_container(std::string name_file, uint64_t key_length)
{
	std::ofstream src_file;
	name_file = name_file + "-key_cont.ctb";
	using namespace ctb::container;

	src_file.open(name_file.c_str(), std::ios::binary);
	if(!src_file.is_open())
		{
			std::cerr <<
					"File dont open!"
					<< std::endl;
			return;
		}

	header hdr{};
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = KEY_DATA;
	hdr.crypt = RAW_CRYPT;
	src_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);

	metadata md{};
	md.length = FILE_METADATA_SIZE;
	md.key.orig_length = key_length;
	md.key.block_size = BLOCK_SIZE;
	md.key.block_count = key_length / (BLOCK_SIZE / 8);
	if (key_length % (BLOCK_SIZE / 8) > 0)
		md.key.block_count++;
	src_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE);
	std::random_device rd;
	std::mt19937 random_mt(rd());
	for (uint64_t block = 0; block < md.key.block_count; block++)
		{
			uint8_t buffer[BLOCK_SIZE / 8] {};
			//src_file.read(reinterpret_cast<char*>(&bufffer[0]),
			//		BLOCK_SIZE / 8);
			srand (static_cast<unsigned int>(time(0)));
			for (uint8_t i = 0; i < BLOCK_SIZE / 8; i++)
			{
				buffer[i] = random_mt() % 256;
			}

			src_file.write(reinterpret_cast<char*>(&buffer[0]),
					BLOCK_SIZE / 8);
		}

	src_file.close();
	std::cout << "Create key container" << std::endl;
}

int main(int argc, char ** argv)
{
	for (int i = 0; i < argc; i++)
		std::cout << argv[i] << std::endl;
	int choose;
	int key_length = 16;
	std::string name_file;
	//ctb::hash::gost_34_11_hash_512();
	{
		std::cout << "Choose an action\n"
				<< "1. Create Key container\n"
				<< "2. Create encryption container\n"
				<< "3. Extract encryption container\n"
				<< "4. Exit"
				<< std::endl;
		std::cin >> choose;
		switch(choose)
		{
		case 1:
			std::cout << "Enter a name for the key container:" << std::endl;
			std::cin >> name_file;
			std::cout << "Enter key length:" << std::endl;
			std::cin >> key_length;
			std::cout << "Name: "<< name_file << std::endl;
			key_container(name_file, key_length);
			break;
		case 2:
			std::cout << "Enter file name:" << std::endl;
			//std::cin >> name_file;
			name_file = "test.txt"; // DEBAG
			std::cout << "Name: "<< name_file << std::endl;
			create_container(name_file);
			break;
		case 3:
			std::cout << "Enter container name:" << std::endl;
			std::cin >> name_file;
			std::cout << "Name: "<< name_file << std::endl;
			extract_container(name_file);
			break;
		case 4:
			exit(0);
			break;
		}
	}

	return 0;
}



