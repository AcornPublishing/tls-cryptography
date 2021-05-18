#include<iostream>
#include"util/option.h"
#include"util/log.h"
#include"tcpip/server.h"
#include"tls.h"
using namespace std;

class TLS_client : public Client
{
public:
	TLS_client(string ip, int port) : Client{ip, port} {
		send(t.client_hello()); LOGD << "client hello" << endl;
		t.server_hello(*recv()); LOGD << "server hello" << endl;
		t.server_certificate(*recv());  LOGD << "server certificate" << endl;
		t.server_key_exchange(*recv()); LOGD << "server key exchange" << endl;
		t.server_hello_done(*recv()); LOGD << "server hello done" << endl;
		string a = t.client_key_exchange();
		string b = t.change_cipher_spec();
		string c = t.finished();
		send(a + b + c);
		t.change_cipher_spec(*recv()); LOGD << "change cipher spec" << endl;
		t.finished(*recv()); LOGD << "handshake finished" << endl;
	}
	void encodeNsend(string s) {
		send(t.encode(move(s)));
	}
	optional<string> recvNdecode() {
		return t.decode(*recv());
	}
private:
	TLS<CLIENT> t;
	int get_full_length(const string &s) {
		return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
	
};

int main(int ac, char **av) {
	CMDoption co{
		{"port", "port of the host", 4433},
		{"ip", "ip address of the host", "localhost"}
	};
	if(!co.args(ac, av)) return 0;
//	TLS<false> t;
	TLS_client t{co.get<const char*>("ip"), co.get<int>("port")};
//	cl.send(t.client_hello());
//	cout << cl.recv();
//	TLS_client t{"localhost", 4433};//co.get<const char*>("ip"), co.get<int>("port")};
	t.encodeNsend("GET /");
	cout << *t.recvNdecode() << endl;
}
