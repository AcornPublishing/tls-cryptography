#include<iostream>
#include"util/log.h"
#include"tls.h"
#include"tcpip/server.h"
using namespace std;

class TServer : public Server {
public:
	TServer(int port) : Server{port} {}
private:
	int get_full_length(const string &s) {
		return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
};


class Func {
public:
	Func() = default;
	Func(const Func &r) { }
	string operator()(string s) {
		string to_send;
		switch(count) {
		case 0 : t.client_hello(move(s));
				 to_send = t.server_hello();
				 to_send += t.server_certificate();
				 to_send += t.server_key_exchange();
				 to_send += t.server_hello_done();
				 break;
		case 1 : t.client_key_exchange(move(s)); break;
		case 2 : t.change_cipher_spec(move(s)); break;
		case 3 : t.finished(move(s));
				 to_send = t.change_cipher_spec();
				 to_send += t.finished();
				 break;
		default: cout << *t.decode(move(s)) << endl;
				 to_send = t.encode("Learning cryptography by implementing TLS");
		}
		count++;
		return to_send;
	}
private:
	static int count;//init 0 outside of main
	TLS<true> t;
};

int Func::count = 0;

int main() {
	Log::get_instance()->set_log_filter("DI");
	TServer sv{4433};
	Func func;
	sv.start(func);
}
