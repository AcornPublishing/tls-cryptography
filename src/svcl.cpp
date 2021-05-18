#include"src/tls.h"
#include<cassert>
#include<iostream>
using namespace std;

int main() {
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
	assert(string{"hello world"} == server.decode(client.encode("hello world")));
	assert(string{"Hello!! world"} == client.decode(server.encode("Hello!! world")));
}



