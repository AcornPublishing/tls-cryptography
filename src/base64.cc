#include<string>
#include<vector>
using namespace std;

static char b2c(unsigned char n)
{//6bit to char
	if(n < 26) return 'A' + n;
	if(n < 52) return 'a' + (n - 26);
	if(n < 62) return '0' + (n - 52);
	return n == 62 ? '+' : '/';
}

static unsigned char c2b(char c)
{//char to 6bit
	if('A' <= c && c <= 'Z') return c - 'A';
	if('a' <= c) return c - 'a' + 26;
	if('0' <= c) return c - '0' + 52;
	return c == '+' ? 62 : 63;
}

string base64_encode(vector<unsigned char> v)
{
	string s;
	int padding = (3 - v.size() % 3) % 3;
	for(int i=0; i<padding; i++) v.push_back(0);
	for(int i=0; i<v.size(); i+=3) {
		s += b2c((v[i] & 0b11111100) >> 2);
		s += b2c((v[i] & 0b00000011) << 4 | (v[i+1] & 0b11110000) >> 4);
		s += b2c((v[i+1] & 0b00001111) << 2 | (v[i+2] & 0b11000000) >> 6);
		s += b2c(v[i+2] & 0b00111111);
	}
	for(int i=0; i<padding; i++) s[s.size() - 1 - i] = '=';
	return s;
}

vector<unsigned char> base64_decode(string s)
{
	int padding = 0;
	for(int i=0; s[s.size()-1-i] == '='; i++) padding++;
	unsigned char bit[4];
	vector<unsigned char> v;
	for(int i=0; i<s.size(); i+=4) {
		for(int j=0; j<4; j++) bit[j] = c2b(s[i+j]);
		v.push_back(bit[0] << 2 | bit[1] >> 4);
		v.push_back(bit[1] << 4 | bit[2] >> 2);
		v.push_back(bit[2] << 6 | bit[3]);
	}
	for(int i=0; i<padding; i++) v.pop_back();
	return v;
}


