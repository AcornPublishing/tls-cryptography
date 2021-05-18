#pragma once
#include<gmpxx.h>
#include<type_traits>
#include<cassert>
#include<vector>
#include<nettle/aes.h>
#include<nettle/cbc.h>
#define Encryption true
#define Decryption false

//정의부
template<bool Enc, int B = 128> class nAES
{
public:
	void key(const mpz_class key);
	void key(const unsigned char* key);
	void iv(const mpz_class iv);
	void iv(const unsigned char* iv);
	template<typename It>
	std::vector<unsigned char> encrypt(const It begin, const It end) {
		const int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		cbc_encrypt(&aes_, (B == 128 ?
					(nettle_cipher_func*)aes128_encrypt :
					(nettle_cipher_func*)aes256_encrypt),
					16, iv_, sz, (uint8_t*)&result[0], 
					(const unsigned char*)&*begin);
		return result;
	}
	template<typename It>
	std::vector<unsigned char> decrypt(const It begin, const It end) {
		const int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		cbc_decrypt(&aes_, (B == 128 ?
					(nettle_cipher_func*)aes128_decrypt :
					(nettle_cipher_func*)aes256_decrypt),
					16, iv_, sz, (uint8_t*)&result[0],
					(const unsigned char*)&*begin);
		return result;
	}
protected:
	typename std::conditional<B == 128, aes128_ctx, aes256_ctx>::type aes_;
	unsigned char iv_[16], key_[32];
private:
	void key();
};

