#pragma once
#include<gmpxx.h>
#include"mpz.h"

struct DiffieHellman
{//256 byte = 2048 bit
	mpz_class set_peer_pubkey(mpz_class pub_key);
	mpz_class p{"0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"};
	mpz_class K, g = 2, x = random_prime(255), y = powm(g, x, p);
};


struct X25519
{
	X25519(mpz_class x = 9, mpz_class y = mpz_class{"14781619447589544791020593568409986887264606134616475288964881837755586237401"});//default is g
	X25519 operator+(const X25519 &r) const;
	X25519 operator*(const mpz_class &k) const;
	bool operator==(const X25519 &r) const;
	X25519 &operator=(const X25519 &r);
	mpz_class mod_inv(const mpz_class &z) const;
	mpz_class x, y;
	static const mpz_class a, mod;//486662, 2^255-19
};

std::ostream& operator<<(std::ostream &is, const X25519 &r);
X25519 operator*(const mpz_class &k, const X25519 &r);

class EC_Field
{
public:
	EC_Field(mpz_class a, mpz_class b, mpz_class mod);
protected:
	//EC_Field(const EC_Field& r);
	mpz_class a, b, mod;
	mpz_class mod_inv(const mpz_class& r) const;
};

struct EC_Point : EC_Field
{
	EC_Point(mpz_class x, mpz_class y, const EC_Field &f);
	mpz_class x, y;
	EC_Point operator+(const EC_Point &r) const;
	EC_Point operator*(mpz_class r) const;
	bool operator==(const EC_Point &r) const;
};
std::ostream& operator<<(std::ostream &is, const EC_Point &r);
EC_Point operator*(const mpz_class &l, const EC_Point &r);
