//#include<iostream>
#include"ecdsa.h"
using namespace std;

ECDSA::ECDSA(const EC_Point &g, mpz_class n) : EC_Point{g}
{
	n_ = n;
	nBit_ = mpz_sizeinbase(n.get_mpz_t(), 2);
}

mpz_class ECDSA::mod_inv(const mpz_class &z) const
{//mod inv of n
	mpz_class r;
	mpz_invert(r.get_mpz_t(), z.get_mpz_t(), n_.get_mpz_t());
	return r;
}

pair<mpz_class, mpz_class> ECDSA::sign(mpz_class m, mpz_class d) const
{//m : hashed message, d : private key of certificate
	int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);
	mpz_class z = m >> max(mBit - nBit_, 0);
	mpz_class k, s, r;
	EC_Point P = *this;
	do {
		do {
			k = random_prime(31);
			P = k * *this;
//			cout << hex << "k * G" << endl << P << endl;
			r = P.x % n_;
//			cout << hex << "r : " << r << endl;
		} while(r == 0);
		s = (mod_inv(k) * (z + r * d)) % n_;
//		cout << hex << "s : " << s << endl;
	} while(s == 0);
	return {r, s};
}

bool ECDSA::verify(mpz_class m, pair<mpz_class, mpz_class> sig, EC_Point Q) const
{//Q pubkey
	auto [r, s] = sig;
	for(auto a : {r, s}) if(a < 1 || a >= n_) return false;

	int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);
	mpz_class z = m >> max(mBit - nBit_, 0);
	mpz_class u1 = z * mod_inv(s) % n_;
	mpz_class u2 = r * mod_inv(s) % n_;
//	cout << z << endl << u1 << endl << u2 << endl;
	EC_Point P = u1 * *this + u2 * Q;
//	cout << P << endl;
	if(P.y == this->mod) return false;//if P is O
	if((P.x - r) % n_ == 0) return true;
	else return false;
}
