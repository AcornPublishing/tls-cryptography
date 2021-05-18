#include<algorithm>
#include<iostream>
#include"catch.hpp"
#include"src/mpz.h"
#include"src/diffie.h"
#include"src/rsa.h"
#include"src/aes.h"
#include"src/naes.h"
#include"src/sha1.h"
#include"src/hmac.h"
#include"src/prf.h"
using namespace std;

TEST_CASE("mpz") {
	uint8_t arr[8];
	mpz_class a{"0x1234567890abcdef"};
	mpz2bnd(a, arr, arr + 8);
	mpz_class b = bnd2mpz(arr, arr + 8);
	REQUIRE(a == b);
}

TEST_CASE("diffie hellman") {
	DiffieHellman Alice;
	DiffieHellman Bob;
	Alice.set_peer_pubkey(Bob.y);
	Bob.set_peer_pubkey(Alice.y);
	REQUIRE(Alice.K == Bob.K);
}

TEST_CASE("rsa") {
	RSA rsa{256};//256 바이트 키 크기
	auto a = rsa.encode(mpz_class{"0x23423423"});
	REQUIRE(0x23423423 == rsa.decode(a));

	mpz_class msg = 0x143214324234_mpz;
	auto b = rsa.sign(msg);
	REQUIRE(rsa.encode(b) == msg);
}

TEST_CASE("sha1") {
	const string s[] = {"abc", 
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
	const char *result[] = {"0xa9993e364706816aba3e25717850c26c9cd0d89d",
							"0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
							"0xa49b2446a02c645bf419f995b67091253a04a259"};
	unsigned char nresult[20];
	SHA1 sha;
	for(int i=0; i<3; i++) {
		mpz2bnd(mpz_class{result[i]}, nresult, nresult + 20);
		auto a = sha.hash(s[i].begin(), s[i].end());
		REQUIRE(equal(a.begin(), a.end(), nresult));
	}
}


TEST_CASE("hmac") {
	const string data[] = {
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen",
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen, with truncated tag"
	};
	const char *key[] = {
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
		"0x000102030405060708090A0B0C0D0E0F10111213",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424\
			34445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F30"
	};
	const char *result[] = {"0x5FD596EE78D5553C8FF4E72D266DFD192366DA29",
							"0x4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
							"0x2D51B2F7750E410584662E38F133435F4C4FD42A",
							"0xFE3529565CD8E28C5FA79EAC9D8023B53B289D96"};

	int data_len[] = {34, 34, 34, 54};
	int key_len[] = {64, 20, 100, 49};
	unsigned char nkey[100], nresult[32];

	HMAC<SHA1> hmac;
	for(int i=0; i<4; i++) {
		mpz2bnd(mpz_class{key[i]}, nkey, nkey + key_len[i]);
		mpz2bnd(mpz_class{result[i]}, nresult, nresult + 20);
		hmac.key(nkey, nkey + key_len[i]);
		auto a = hmac.hash(data[i].begin(), data[i].end());
		REQUIRE(equal(a.begin(), a.end(), nresult));
	}
	auto a = hmac.hash(data[3].begin(), data[3].end());
	REQUIRE(equal(a.begin(), a.end(), nresult));
	REQUIRE(hmac.hash(data[2].begin(), data[2].end()) == hmac.hash(data[2].begin(), data[2].end()));
}

TEST_CASE("prf") {
	PRF<SHA1> prf;
	unsigned char seed[100], secret[100];
	vector<vector<unsigned char>> vv; 
	mpz_class z1{"0x3a64b675191395ba19842ad7d14c2d798fe9e2dab6b9ebcdfab50ec68a862691effbff693bc68643a6463c71b322c9d7cb3e0b29c15dbee6d11d42667a014183"};
	mpz_class z2{"0xc5048557a1a02314403003ee56326aaf33bc3c10fd7f00007280a784ca5500006b9ccfad52e06aedb01f4eab6c2caaa6"};
	mpz_class res{"0x3b6b817ecb6fd456d4989b24832ecdad44a8349bc0c7551d84fb2da638909846fbb1f984f4b35b6ff7103e687493b3e7b7296096fcb3ee8358082da129eaceb4766e1f20cdf25901"};
	int sz1 = (mpz_sizeinbase(z1.get_mpz_t(), 16) + 1) / 2;
	int sz2 = (mpz_sizeinbase(z2.get_mpz_t(), 16) + 1) / 2;
	mpz2bnd(z1, seed, seed + sz1);
	mpz2bnd(z2, secret, secret + sz2);
	prf.label("master secret");
	prf.seed(seed, seed + sz1);
	prf.secret(secret, secret + sz2);
	auto a = prf.get_n_byte(72);
	auto b = prf.get_n_byte2(72);
	REQUIRE(a == b);
	REQUIRE(res == bnd2mpz(a.begin(), a.end()));
}

