#include<gmpxx.h>
#include<iomanip>
#include<istream>
#include<string>
#include"cert_util.h"
using namespace std;

string get_certificate_core(istream& is) {//if certificate has no -----END hang..
	string s, r;
	while(s != "-----BEGIN") if(!(is >> s)) return r;//no more certificate
	getline(is, s);
	for(is >> s; s != "-----END"; is >> s) r += s;
	return r;
}

mpz_class str2mpz(string s) {
	stringstream ss; char c; string r = "0x";
	ss << s;
	while(ss >> setw(2) >> s >> c) r += s;
	return mpz_class{r};
}

Json::Value pem2json(istream& is) {
	auto v = base64_decode(get_certificate_core(is));
	stringstream ss;
	for(auto c : v) ss << c;
	return der2json(ss);
}

array<mpz_class, 2> process_bitstring(string s)
{//RSA bitstring should be reprocessed to get the modulus and exponent
	stringstream ss, ss2; char c;
	ss << s;
	ss >> setw(2) >> s >> c;//garbage
	while(ss >> setw(2) >> s >> c) {
		c = stoi(s, nullptr, 16);
		ss2 << c;
	}
	auto jv = der2json(ss2);
	return {str2mpz(jv[0][0].asString()), str2mpz(jv[0][1].asString())};
}

array<mpz_class, 3> get_pubkeys(const Json::Value& jv)
{
	auto [a, b] = process_bitstring(jv[0][0][6][1].asString());//asString remove " ";
	auto c = str2mpz(jv[0][2].asString());//signature
	return {a, b, c};//K, e, signature
}

array<mpz_class, 3> get_pubkeys(istream& is)
{//array = {RSA modulus, RSA exponent, sha sign}
	return get_pubkeys(pem2json(is));
}

array<mpz_class, 3> get_keys(istream& is)//is key.pem
{
	return get_keys(pem2json(is));
	//return {str2mpz(jv[0][1].asString()), str2mpz(jv[0][2].asString()), str2mpz(jv[0][3].asString())};
}

array<mpz_class, 3> get_keys(const Json::Value &jv)
{
	return {str2mpz(jv[0][1].asString()), str2mpz(jv[0][2].asString()), str2mpz(jv[0][3].asString())};
}
