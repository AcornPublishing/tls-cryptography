#include<iomanip>
#include<iostream>
#include<algorithm>
#include<nettle/gcm.h>
#include<nettle/aes.h>
#include"catch.hpp"
#include"src/mpz.h"
#define private public
#define protected public
#include"src/aes.h"
#undef private
#undef protected
#include"src/naes.h"
using namespace std;

unsigned char schedule[11 * 16] = {
	0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 
	0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75,
	0xE2, 0x32, 0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88, 
	0xB1, 0x59, 0xE4, 0xE6, 0xD6, 0x79, 0xA2, 0x93,
	0x56, 0x08, 0x20, 0x07, 0xC7, 0x1A, 0xB1, 0x8F, 
	0x76, 0x43, 0x55, 0x69, 0xA0, 0x3A, 0xF7, 0xFA,
	0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A, 0xBC, 0x68,
	0x63, 0x39, 0xE9, 0x01, 0xC3, 0x03, 0x1E, 0xFB,
	0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1,
	0xD7, 0x51, 0x57, 0xA0, 0x14, 0x52, 0x49, 0x5B,
	0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92,
	0xD2, 0x10, 0xD2, 0x32, 0xC6, 0x42, 0x9B, 0x69,
	0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15,
	0x6A, 0x6C, 0x95, 0x27, 0xAC, 0x2E, 0x0E, 0x4E,
	0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03,
	0x1E, 0x86, 0x3F, 0x24, 0xB2, 0xA8, 0x31, 0x6A,
	0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22,
	0xE4, 0x3D, 0x7A, 0x06, 0x56, 0x95, 0x4B, 0x6C,
	0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2,
	0xA1, 0x64, 0x80, 0xB4, 0xF7, 0xF1, 0xCB, 0xD8,
	0x28, 0xFD, 0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A,
	0xCC, 0xC0, 0xA4, 0xFE, 0x3B, 0x31, 0x6F, 0x26
};

TEST_CASE("key scheduling") {
	AES aes;
	aes.key(schedule);//첫 16바이트만 키 값으로 주어진다.
	REQUIRE(equal(schedule, schedule + 11*16, aes.schedule_[0]));
}

TEST_CASE("shift_row & mix column") {
	AES aes;
	unsigned char data[16], oneto16[16];
	for(int i=0; i<16; i++) data[i] = oneto16[i] = i+1;
	unsigned char shift_row_result[16] 
		= { 1, 6, 0x0b, 0x10, 5, 0xa, 0xf, 4, 9, 0xe, 3, 8, 0xd, 2, 7, 0xc };
	unsigned char mix_comlumn_result[16]
		= {3, 4, 9, 0xa, 0xf, 8, 0x15, 0x1e, 0xb, 0xc, 1, 2, 0x17, 0x10, 0x2d, 0x36};

	aes.shift_row(data);
	REQUIRE(equal(data, data + 16, shift_row_result));
	aes.inv_shift_row(data);
	REQUIRE(equal(data, data + 16, oneto16));

	aes.mix_column(data);
	REQUIRE(equal(data, data + 16, mix_comlumn_result));
	aes.inv_mix_column(data);
	REQUIRE(equal(data, data + 16, oneto16));
}

TEST_CASE("compare aes result with nettle") {
	unsigned char key[16], iv[16], plain_text[64];
	mpz2bnd(mpz_class{"0x2B7E151628AED2A6ABF7158809CF4F3C"}, key, key+16);
	mpz2bnd(mpz_class{"0x000102030405060708090A0B0C0D0E0F"}, iv, iv+16);
	mpz2bnd(mpz_class{"0x6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76\
			FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417\
			BE66C3710"}, plain_text, plain_text + 64);
	
	CBC<AES> aes; nAES<Encryption> naes; nAES<Decryption> naesd;
	aes.key(key); naes.key(key); naesd.key(key);
	aes.iv(iv); naes.iv(iv); naesd.iv(iv);

	unsigned char original[64], encrypted[64], decrypted[64];
	memcpy(original, plain_text, 64);
	aes.encrypt(plain_text, 64);
	memcpy(encrypted, plain_text, 64);
	aes.decrypt(plain_text, 64);
	memcpy(decrypted, plain_text, 64);
	REQUIRE(equal(original, original + 64, decrypted));

	auto v = naes.encrypt(original, original + 64);
	REQUIRE(equal(v.begin(), v.end(), encrypted));
	v = naesd.decrypt(v.begin(), v.end());
	REQUIRE(equal(v.begin(), v.end(), original));
}

TEST_CASE("GCM") {
	unsigned char K[16], A[70], IV[12], P[48], Z[16], C[48];
	mpz2bnd(random_prime(16), K, K + 16);
	mpz2bnd(random_prime(70), A, A + 70);
	mpz2bnd(random_prime(12), IV, IV + 12);
	mpz2bnd(random_prime(48), P, P + 48);
	SECTION("GCM compare with nettle") {
		gcm_aes128_ctx ctx;
		gcm_aes128_set_key(&ctx, K);
		gcm_aes128_set_iv(&ctx, 12, IV);
		gcm_aes128_update(&ctx, 28, A);
		gcm_aes128_encrypt(&ctx, 48, C, P);
		gcm_aes128_digest(&ctx, 16, Z);

		GCM<AES> gcm;
		gcm.iv(IV);
		gcm.key(K);
		gcm.aad(A, 28);
		auto a = gcm.encrypt(P, 48);
		REQUIRE(equal(P, P+48, C));
		REQUIRE(equal(a.begin(), a.end(), Z));

		mpz2bnd(random_prime(12), IV, IV+12);
		mpz2bnd(random_prime(70), A, A + 70);
		gcm_aes128_set_iv(&ctx, 12, IV);
		gcm_aes128_update(&ctx, 28, A);
		gcm_aes128_encrypt(&ctx, 48, C, P);
		gcm_aes128_digest(&ctx, 16, Z);
		
		gcm.iv(IV);
		gcm.aad(A, 28);
		a = gcm.encrypt(P, 48);
		REQUIRE(equal(P, P+48, C));
		REQUIRE(equal(a.begin(), a.end(), Z));
	}
}

TEST_CASE("inverse mix coulumn matrix verify") {
	AES aes;
	unsigned char inv[16] = {
		14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14
	};
	unsigned char o[16] = { 1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1};

	aes.mix_column(inv);
	REQUIRE(equal(inv, inv + 16, o));
}

TEST_CASE("CBC") {
	CBC<AES> cbc;
	unsigned char key[16] = {
		14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14
	};
	unsigned char iv[16] = {
		1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1
	};
	cbc.key(key);
	cbc.iv(iv);
	string msg = "Hello this is test";

	for(int i=0; i<14; i++) msg += 13;
	cbc.encrypt((unsigned char*)msg.data(), 32);
	cbc.decrypt((unsigned char*)msg.data(), 32);
	for(int i=msg.back(); i >= 0; i--) msg.pop_back();//패딩 제거
	REQUIRE(msg == "Hello this is test");
}
