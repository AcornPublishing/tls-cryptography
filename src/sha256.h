#pragma once
#include<array>
#include<nettle/sha2.h>
#include<nettle/sha3.h>

class SHA2
{
public:
	static const int block_size = 64;
	static const int output_size = 32;
	SHA2() {
		sha256_init(&sha_);
	}
	template<typename It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha256_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha256_digest(&sha_, output_size, &r[0]);
		return r;
	}
protected:
	sha256_ctx sha_;
};

//class SHA5
//{//sha512
//public:
//	static const int block_size = 128;
//	static const int output_size = 64;
//	SHA5() {
//		sha512_init(&sha_);
//	}
//	template<class It>
//	std::array<unsigned char, output_size> hash(const It begin, const It end) {
//		std::array<unsigned char, output_size> r;
//		sha512_update(&sha_, end - begin, (const unsigned char*)&*begin);
//		sha512_digest(&sha_, output_size, &r[0]);
//		return r;
//	}
//protected:
//	sha512_ctx sha_;
//};
