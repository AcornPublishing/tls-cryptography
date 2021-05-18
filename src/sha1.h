#pragma once
#include<array>
#include<vector>
#include<netinet/in.h>

class SHA1
{
public:
	static const int block_size = 64;
	static const int output_size = 20;
	SHA1();
	template<class It> std::array<unsigned char, 20> hash(const It begin, const It end)
	{
		for(int i=0; i<5; i++) h[i] = h_stored_value[i];
		std::vector<unsigned char> msg(begin, end);
		preprocess(msg);
		for(int i=0; i<msg.size(); i+=64) process_chunk(&msg[i]);
		if(!big_endian_) for(int i=0; i<5; i++) h[i] = htonl(h[i]);
		std::array<unsigned char, 20> digest;
		unsigned char *p = (unsigned char*)h;
		for(int i=0; i<20; i++) digest[i] = *p++;
		return digest;
	}

protected:
	bool big_endian_ = false;
	uint32_t h[5], w[80];
	static constexpr uint32_t h_stored_value[5] =
		{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

private:
	static void preprocess(std::vector<unsigned char> &v);
	void process_chunk(unsigned char *p);//64 byte chunk
};


