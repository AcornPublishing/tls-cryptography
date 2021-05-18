#include<vector>
#include<iostream>
using namespace std;

int powm(int base, int exp, int mod) {
	int r = 1;
	for(int i=0; i<exp; i++) {
		r *= base;
		r %= mod;
	}
	return r;
}

bool is_primitive(int base, int mod) {//mod should be prime number
	int exp = 2;
	int r = base * base;
	for(; r != base; exp++) {
		r *= base;
		r %= mod;
	} 
	return exp == mod;
}

vector<int> primitive_root(int mod) {
	vector<int> v;
	for(int base=2; base<mod; base++) if(is_primitive(base, mod)) v.push_back(base);
	return v;
}

int main() {
	cout << powm(3, 100, 23) << endl;
	for(int i : primitive_root(29)) cout << i << ',';
	cout << endl;
}
