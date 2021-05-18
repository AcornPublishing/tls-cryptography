#include<cassert>
#include<vector>
#include"mpz.h"
#include"diffie.h"
using namespace std;

//DiffieHellman::DiffieHellman(mpz_class p, mpz_class g, mpz_class ya)
//{//client side
//	this->p = p; this->g = g; this->ya = ya;
//	xb = random_prime(256);
//	yb = powm(g, xb, p);
//	K = powm(ya, xb, p);
//}
mpz_class DiffieHellman::set_peer_pubkey(mpz_class pub_key)
{//set client pub key
	K = powm(pub_key, x, p);
	return K;
}

static mpz_class init_mod()
{//retrun 2^255 - 19
	mpz_class mod;
	mpz_ui_pow_ui(mod.get_mpz_t(), 2, 255);
	mod -= 19;
	return mod;
}

const mpz_class X25519::mod = init_mod();
const mpz_class X25519::a = 486662;

X25519::X25519(mpz_class x, mpz_class y)
{
	this->x = x; this->y = y;
}

X25519 &X25519::operator=(const X25519 &r) 
{//y^2 = x^3 + ax^2 + x, ?? elliptic curve y^2 = x^3 + ax + b
	x = r.x; y = r.y;
	return *this;
}

mpz_class X25519::mod_inv(const mpz_class &z) const {
	mpz_class r;
	mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
	return r;
}

X25519 X25519::operator+(const X25519 &q) const
{//return Xr <- p + q
	mpz_class s;
	if(*this == q) s = (3*q.x*q.x + 2*a*q.x + 1) * mod_inv(2 * q.y) % mod;
	else s = (this->y - q.y) * mod_inv(this->x - q.x) % mod;
	X25519 r;
	r.x = (s*s - 3*a - this->x - q.x) % mod;
	r.y = (s * (this->x - r.x) - this->y) % mod;
	if(r.x < 0) r.x += mod;
	if(r.y < 0) r.y += mod;
	return r;
}

X25519 X25519::operator*(const mpz_class &k) const
{//return kp
	vector<bool> bin;//k = 2^0 + 2^4 + 2^5 + 2^17 + .. + 2^n 
	for(mpz_class i=0, r=1, flag; i<k; i++, r *= 2) { 
		mpz_and(flag.get_mpz_t(), k.get_mpz_t(), r.get_mpz_t());
		bin.push_back(flag != 0);
	}
	X25519 R, X = *this;
	int first = 0;
	for(auto a : bin) {
		if(a) R = !first++ ? X : R + X;
		X = X + X;
	}
	return R;
}

X25519 operator*(const mpz_class &k, const X25519 &r)
{
	return r * k;
}

bool X25519::operator==(const X25519 &r) const
{
	return x == r.x && y == r.y;
}

ostream& operator<<(ostream &os, const X25519 &r)
{
	os << hex << '(' << r.x << ",\n " << r.y << ')';
	return os;
}

ostream& operator<<(ostream &os, const EC_Point &r)
{
	os << '(' << r.x << ", " << r.y << ')';
	return os;
}
EC_Field::EC_Field(mpz_class a, mpz_class b, mpz_class mod)
{//y^2 = x^3 + ax^2 + b
	this->a = a;
	this->b = b;
	this->mod = mod;
}

//EC_Field::EC_Field(const EC_Field& r)
//{
//	this->a = r.a;
//	this->b = r.b;
//	this->mod = r.mod;
//}

EC_Point::EC_Point(mpz_class x, mpz_class y, const EC_Field &f) : EC_Field{f}
{
	if(y != mod) assert((y*y - (x*x*x + a*x + b)) % mod == 0);
	this->x = x;
	this->y = y;
}

bool EC_Point::operator==(const EC_Point &r) const{
	assert(a == r.a && b == r.b && mod == r.mod);
	return x == r.x && y == r.y;
}
EC_Point EC_Point::operator+(const EC_Point &r) const
{//y == mod -> O : infinity
	if(r.y == mod) return *this;//P + O = P
	if(y == mod) return r;// O + P = P
	mpz_class s;//slope
	if(r == *this) {//2P
		if(y == 0) return {x, mod, *this};
		s = (3 * x * x + a) * this->mod_inv(2 * y) % mod;
	} else {
		if(x == r.x) return {x, mod, *this};
		s = (r.y - y) * this->mod_inv(r.x - x) % mod;
	}
	mpz_class x3 = (s * s - x - r.x) % mod;
	mpz_class y3 = (s * (x - x3) - y) % mod;
	return {x3 < 0 ? x3 + mod : x3, y3 < 0 ? y3 + mod : y3, *this};
}
EC_Point EC_Point::operator*(mpz_class r) const
{
	vector<bool> v;
	for(; r > 0; r /= 2) v.push_back(r % 2 == 1);
	EC_Point X = *this, R{0, mod, *this};
	for(auto a : v) {
		if(a) R = R + X;
		X = X + X;
	}
	return R;
}

EC_Point operator*(const mpz_class &l, const EC_Point &r) {
	return r * l;
}
mpz_class EC_Field::mod_inv(const mpz_class &z) const
{
	mpz_class r;
	mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
	return r;
}
