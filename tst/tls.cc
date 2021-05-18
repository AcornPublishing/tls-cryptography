#include"catch.hpp"
#include"util/log.h"
#define private public
#define protected public
#include"src/mpz.h"
#include"src/diffie.h"
#include"src/tls.h"
#include"src/tls13.h"
#undef private
#undef protected
#include<iostream>
using namespace std;

TEST_CASE("tls") {
	Log::get_instance()->set_log_filter("TdIWEF");
	TLS<true> server; TLS<false> client;
	server.client_hello(client.client_hello());
	client.server_hello(server.server_hello());
	client.server_certificate(server.server_certificate());
	client.server_key_exchange(server.server_key_exchange());
	client.server_hello_done(server.server_hello_done());
	server.client_key_exchange(client.client_key_exchange());
	server.change_cipher_spec(client.change_cipher_spec());
	server.finished(client.finished());
	client.change_cipher_spec(server.change_cipher_spec());
	client.finished(server.finished());//error
//	REQUIRE(server.diffie_.K == client.diffie_.K);
	REQUIRE(equal(server.master_secret_.begin(), server.master_secret_.end(),
				client.master_secret_.begin()));
	REQUIRE(equal(server.client_random_.begin(), server.client_random_.end(),
				client.client_random_.begin()));
	REQUIRE(equal(server.server_random_.begin(), server.server_random_.end(),
				client.server_random_.begin()));
	for(int i=0; i<2; i++) {//check key expansion
		REQUIRE(equal(server.aes_[i].cipher_.schedule_[0],
					server.aes_[i].cipher_.schedule_[0] + 11*16,
					client.aes_[i].cipher_.schedule_[0]));
	}
	//LOGD << server.decode(client.encode("hello world")) << endl;
	REQUIRE(server.decode(client.encode("hello world")) == "hello world");
	REQUIRE(client.decode(server.encode("Hello!! world")) == "Hello!! world");
}

TEST_CASE("tls13 client hello") {
	uint8_t cl_hello[517];
	mpz_class msg{"0x1603010200010001fc0303c299e5f06af1f9c689e797b65e418bf9476fe7f725a437690e9546419b5158d4201cb59a8af4e5dea42d14ab61bf008b84cb3a21183de118818f246aab4697efc30024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f0000000e000c0000096c6f63616c686f737400170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d0020539ffe32e28a361b6a487db18a5adf289a570e7790761c7f9e53ed0bdc01193e0017004104da6a3bc12c8558dbf85cd21f1bebf53b28ac4885737b49b872bbd6340d568038ea27eaaf0ae2056bc1d531374831d086e188e6e1d7ff1d22df93598dfba820cb002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
	mpz2bnd(msg, cl_hello, cl_hello + 517);
	REQUIRE(cl_hello[76] == 0);
	REQUIRE(cl_hello[77] == 0x24);
	REQUIRE(cl_hello[0x24 + 80] == 1);
	REQUIRE(cl_hello[0x24 + 81] == 0x8f);
	TLS13<SERVER> t;
	t.client_hello(string{cl_hello, cl_hello + 517});
}



TEST_CASE("tls13 server hello") {
	mpz_class msg{"0x160303009b02000097030301b270baa8babbd0f09002f138ee2f996db92dc93c931b48692d10f0c5d38ae3200000000000000000000000000000000000000000000000000000000000000000c02f00004f002b00020304003300450017004104107b0d2c5d45ba8c121c4e2b0317747e3db336f65682c05e82c970d2f44ee5bd107b0d2c5d45ba8c121c4e2b0317747e3db336f65682c05e82c970d2f44ee5bd"};
	EC_Field secp256r1{
		mpz_class{"0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"},
		mpz_class{"0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"}, 
		mpz_class{"0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"}
	};
	uint8_t sv_hello[160];
	mpz2bnd(msg, sv_hello, sv_hello + 160);
	REQUIRE(sv_hello[79] == 0);
	REQUIRE(sv_hello[80] == 0x4f);
//	EC_Point P{bnd2mpz(sv_hello + 96, sv_hello + 128), bnd2mpz(sv_hello + 128, sv_hello + 160), secp256r1};
}	
