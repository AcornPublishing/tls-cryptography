#include<iostream>
#include"tcpip/server.h"
using namespace std;

int main() {
	Server sv{2002};
	sv.start([](string s) {
			cout << s << " received" << endl;
			return "Learn cryptography by implementing TLS";
	});
}


