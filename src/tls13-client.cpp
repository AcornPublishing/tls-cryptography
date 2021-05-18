#include<iostream>
#include"util/option.h"
#include"util/log.h"
#include"tcpip/server.h"
#include"tls13.h"
using namespace std;

class TLS_client : public Client
{
public:
	TLS_client(string ip, int port) : Client{ip, port} {
		t.handshake(bind(&TLS_client::recv, this, 0),
				bind(&TLS_client::send, this, placeholders::_1, 0));
	}
	void encodeNsend(string s) {
		send(t.encode(move(s)));
	}
	optional<string> recvNdecode() {
		return t.decode(*recv());
	}
private:
	TLS13<CLIENT> t;
	int get_full_length(const string &s) {
		return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100
			+ static_cast<unsigned char>(s[4]) + 5;
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
for(int i=0; i<10000; i++) {
	t.encodeNsend("GET /");
	cout << *t.recvNdecode() << endl;}	
}

