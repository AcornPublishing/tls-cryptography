#include<iomanip>
#include<fstream>
#include<string>
#include<iostream>
#include<sstream>
#include"cert_util.h"
using namespace std;

int main(int ac, char **av) {
	if(ac < 2) {
		cout << "usage : " << av[0] << " [pem file]" << endl;
		return 1;
	}
	ifstream f(av[1]);
	for(string s; (s = get_certificate_core(f)) != "";) {
		auto v = base64_decode(s);
		stringstream ss;
		for(uint8_t c : v) ss << c;
		auto jv = der2json(ss);
		cout << jv << endl;
	}
//	if(jv[0].size() == 3) {
//		auto [K,e,sign] = get_pubkeys(jv);
//		cout << hex << "K : " << K << "\ne : " << e << "\nsign : " << sign << endl;
//	} else {
//		auto [K, e, sign] = get_keys(jv);
//		cout << hex << "K : " << K << "\ne : " << e << "\nsign : " << sign << endl;
//	}
}

