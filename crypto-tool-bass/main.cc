/*
 * main.cc
 *
 *  Created on: 22 сент. 2021 г.
 *      Author: Lev
 */
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdint.h>
#include <algorithm>

//#include <ctb-container.h>

#include "ctb-container.h"
const uint32_t BLOCK_SIZE = 32;

void create_container(std::string name_file)
{
	std::ifstream src_file;
	std::ofstream dst_file;
	std::string container_name_file = name_file + "-container.ctb";
	src_file.open(name_file.c_str(), std::ios::binary | std::ios::ate);

	if(!src_file.is_open())
	{
		std::cerr <<
				"Файл не открыт!"
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
		uint8_t bufffer[BLOCK_SIZE / 8] {};
		src_file.readsome(reinterpret_cast<char*>(&bufffer[0]),
				BLOCK_SIZE / 8);
		dst_file.write(reinterpret_cast<char*>(&bufffer[0]),
				BLOCK_SIZE / 8);
	}

	src_file.close();
	dst_file.close();

}

void extract_container(std::string name_file)
{
	std::ifstream src_file;
	std::ofstream dst_file;

	std::string container_name_file = name_file + "-container.ctb";


	using namespace ctb::container;

	src_file.open(container_name_file.c_str(), std::ios::binary);
	header hdr {};
	src_file.readsome(reinterpret_cast<char*>(&hdr),
			sizeof(header));
	if (hdr.magic != MAGIC) {
			std::cerr <<
					"Контейнер неправильный!"
					<< std::endl;
			return;
		}
	if (hdr.payload != RAW) {
		std::cerr <<
				"В контейнере лежит не RAW!"
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
}

int main(int argc, char ** argv)
{
	std::string name_file;
	std::cout << "Введите название файла" << std::endl;
	std::cin >> name_file;
	std::cout << "Start" << std::endl;
	create_container(name_file);
	std::cout << "Create container" << std::endl;
	extract_container(name_file);
	std::cout << "Extract container" << std::endl;

	return 0;
}



