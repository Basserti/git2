/*
 * main.cc
 *
 *  Created on: 22 ����. 2021 �.
 *      Author: Lev
 */
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdint.h>
#include <cstdlib>
#include <random>
#include <algorithm>

//#include <ctb-container.h>

#include "ctb-container.h"
const uint32_t BLOCK_SIZE = 32;
const uint32_t T_SWAP[16] = {3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14};
//                           0  1  2  3  4  5   6   7   8  9  10  11 12 13 14  15

void create_container(std::string name_file)
{
	std::ifstream src_file;
	std::ofstream dst_file;
	std::string container_name_file = name_file + "-container.ctb";
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

	dst_file.open(container_name_file.c_str(), std::ios::binary);

	using namespace ctb::container;

	header hdr{};
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = RAW;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);

	metadata md{};
	uint32_t name_length =strlen(name_file.c_str());
	md.length = FILE_METADATA_SIZE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = BLOCK_SIZE;
	md.file.block_count = filesize / (BLOCK_SIZE / 8);
	if (filesize % (BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE);
	dst_file.write(name_file.c_str(), name_length + 1);

	for (uint64_t block = 0; block < md.file.block_count; block++)
	{
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		dst_file.write(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
	}

	src_file.close();
	dst_file.close();
	std::cout << "Create container" << std::endl;

}

void extract_container(std::string name_file)
{
	std::ifstream src_file;
	std::ofstream dst_file;
	std::string container_name_file = name_file + "-container.ctb";


	using namespace ctb::container;

	src_file.open(container_name_file.c_str(), std::ios::binary);
	header hdr {};
	src_file.read(reinterpret_cast<char*>(&hdr),
			sizeof(header));
	if (hdr.magic != MAGIC) {
			std::cerr <<
					"File dont open!"
					<< std::endl;
			return;
		}
	if (hdr.payload != RAW) {
		std::cerr <<
				"File no RAW data!"
				<< std::endl;
		return;
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

	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);

	while(md.file.orig_length > 0)
		{
			uint8_t buffer[BLOCK_SIZE / 8] {};
			src_file.read(reinterpret_cast<char*>(&buffer[0]),
					BLOCK_SIZE / 8);
			uint64_t bytes_to_write = std::min<unsigned long>(4UL, md.file.orig_length);
			dst_file.write(
					reinterpret_cast<char*>(&buffer[0]),
					bytes_to_write);
			md.file.orig_length -= bytes_to_write;

		}

	dst_file.close();
	src_file.close();

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

void crypto_container(std::string name_file, std::string name_key_cont_file){

	std::ifstream src_file;
	std::ofstream dst_file;
	std::string container_name_file = name_file + "-crypto_cont.ctb";
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

	dst_file.open(container_name_file.c_str(), std::ios::binary);

	using namespace ctb::container;

	header hdr{};
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = ENCRYPTED_DATA;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);

	metadata md{};
	uint32_t name_length =strlen(name_file.c_str());
	md.length = FILE_METADATA_SIZE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = BLOCK_SIZE;
	md.file.block_count = filesize / (BLOCK_SIZE / 8);
	if (filesize % (BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE);
	dst_file.write(name_file.c_str(), name_length + 1);



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
			if (hdr2.payload != KEY_DATA) {
					std::cerr <<
						"File no KEY_DATA data!"
						<< std::endl;
					return;
			}
			src2_file.seekg(hdr2.header_size);

			uint64_t pos_after_header = src2_file.tellg();

			metadata md2 {};
			src2_file.readsome(reinterpret_cast<char*>(&md2),
					FILE_METADATA_SIZE);
			src2_file.seekg(pos_after_header + md2.length);

			uint8_t key[16] {};
				src2_file.read(reinterpret_cast<char*>(&key[0]),
						16);
				//std::cout << reinterpret_cast<char*>(&key[0]) << std::endl;

			src2_file.close();
			std::cout << "Key read OK!" << std::endl;


	for (uint64_t block = 0; block < md.file.block_count; block++)
		{
			uint8_t buffer[BLOCK_SIZE / 8] {};
			src_file.read(reinterpret_cast<char*>(&buffer[0]),
					BLOCK_SIZE / 8);
			uint8_t *forMerge = new uint8_t[2];
			forMerge[0] = buffer[0];
			forMerge[1] = buffer[1];
			uint16_t Li =  *((uint16_t*)forMerge);
			forMerge[0] = buffer[2];
			forMerge[1] = buffer[3];
			uint16_t Ri =  *((uint16_t*)forMerge);
			//std::cout << " " <<std::endl;
			//std::cout << Li << " " << Ri <<std::endl;

			for(uint16_t ttt=0; ttt<8; ttt++)
			{
			uint16_t a[4] {};
			uint32_t y = 0;
			for(uint32_t i = 0; i < 16; i=i+4)
			{
				a[y] = (((Li >> (i+3)) & 1) << 0) | (((Li >> (i+2)) & 1) << 1) | (((Li >> (i+1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8) | (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[ttt * 2];
			forMerge2[1] = key[ttt * 2 + 1];
			uint16_t key_buff =  *((uint16_t*)forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16-3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
			//std::cout << Li << " " << Ri <<std::endl;
			}
			//std::cout << reinterpret_cast<char*>(&Ri) << std::endl;
			//std::cout << reinterpret_cast<char*>(&Li) << std::endl;
			dst_file.write(reinterpret_cast<char*>(&Ri),
					BLOCK_SIZE / 16);
			dst_file.write(reinterpret_cast<char*>(&Li),
								BLOCK_SIZE / 16);
		}

	src_file.close();
	dst_file.close();
	std::cout << "Crypto container" << std::endl;
}

void extract_crypto_container(std::string name_file, std::string name_key_cont_file)
{
	std::ifstream src_file;
		std::ofstream dst_file;
		std::string container_name_file = name_file + "-crypto_cont.ctb";


		using namespace ctb::container;

		src_file.open(container_name_file.c_str(), std::ios::binary);
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
		src_file.seekg(hdr.header_size);

		uint64_t pos_after_header = src_file.tellg();

		metadata md {};
		src_file.readsome(reinterpret_cast<char*>(&md),
				FILE_METADATA_SIZE);
		std::string orig_file_name = "EXTRACTED_CRYPTO_";
		char c;
		while ((c = src_file.get()))
		{
			orig_file_name += c;
		}

		dst_file.open(orig_file_name.c_str(), std::ios::binary);
		src_file.seekg(pos_after_header + md.length);



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
					if (hdr2.payload != KEY_DATA) {
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

					uint8_t key2[16] {};
						src2_file.read(reinterpret_cast<char*>(&key2[0]),
								16);
						/*for(uint32_t ewq = 0; ewq < sizeof(key2)/sizeof(key2[0]);ewq++){
							std::cout << key2[ewq] << std::endl;
						}
						std::cout << reinterpret_cast<char*>(&key2[0]) << std::endl;*/

					src2_file.close();
					std::cout << "Key read OK!" << std::endl;


		while(md.file.orig_length > 0)
			{
				uint8_t buffer[BLOCK_SIZE / 8] {};
				src_file.read(reinterpret_cast<char*>(&buffer[0]),
						BLOCK_SIZE / 8);

				uint8_t *forMerge = new uint8_t[2];
					forMerge[0] = buffer[0];
					forMerge[1] = buffer[1];
				uint16_t Li =  *((uint16_t*)forMerge);
					forMerge[0] = buffer[2];
					forMerge[1] = buffer[3];
				uint16_t Ri =  *((uint16_t*)forMerge);
				//std::cout << " " <<std::endl;
				//std::cout << Li << " " << Ri <<std::endl;

				for(uint16_t ttt=0; ttt<8; ttt++)
				{
					uint16_t a[4] {};
					uint32_t y = 0;
					for(uint32_t i = 0; i < 16; i=i+4)
					{
						a[y] = (((Li >> (i+3)) & 1) << 0) | (((Li >> (i+2)) & 1) << 1) | (((Li >> (i+1)) & 1) << 2) | (((Li >> i) & 1) << 3);
						y += 1;
					}

					uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8) | (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);
					//std::cout << Li << " " << Ri <<std::endl;
					uint8_t *forMerge2 = new uint8_t[2];
					forMerge2[0] = key2[15 - (ttt * 2 + 1)];
					forMerge2[1] = key2[15 - (ttt * 2)];
					uint16_t key_buff =  *((uint16_t*)forMerge2);

					Sx ^= key_buff;

					Sx = (Sx << 3) | (Sx >> (16-3));

					uint16_t oldLi = Li;
					Li = Ri ^ Sx;
					Ri = oldLi;

					//std::cout << Li << " " << Ri <<std::endl;

				}

				uint16_t *forMargePart = new uint16_t[2];
					forMargePart[0] = Ri;
					forMargePart[1] = Li;
				uint32_t enc_Part = *((uint32_t*)forMargePart);

				uint64_t bytes_to_write = std::min<unsigned long>(4UL, md.file.orig_length);
				dst_file.write(reinterpret_cast<char*>(&enc_Part),
						bytes_to_write);
				md.file.orig_length -= bytes_to_write;

			}

		dst_file.close();
		src_file.close();

		std::cout << "Extract Crypto container" << std::endl;
}

int main(int argc, char ** argv)
{
	for (int i = 0; i < argc; i++)
		std::cout << argv[i] << std::endl;
	std::string name_file;
	std::string key_cont_name = "1-key_cont.ctb";
	uint64_t key_length;
	std::cout << "File name:" << std::endl;
	std::cin >> name_file;
	std::cout << "Key cont name:" << std::endl;
	std::cout << key_cont_name << std::endl;
	//std::cin >> key_cont_name;
	//std::cout << "Key length:" << std::endl;
	//std::cin >> key_length;
	std::cout << "Start" << std::endl;
	//key_container(name_file, key_length);
	//create_container(name_file);
	crypto_container(name_file, key_cont_name);
	//key_from_container(name_file);
	//extract_container(name_file);
	extract_crypto_container(name_file, key_cont_name);

	return 0;
}



