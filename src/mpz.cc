#include<cassert>
#include<random>
#include"mpz.h"
using namespace std;

mpz_class nextprime(mpz_class n) 
{//chance of composite passing will be extremely small
	mpz_class r;
	mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
	return r;
}

mpz_class random_prime(unsigned byte)
{//return byte length prime number
	unsigned char arr[byte];
	uniform_int_distribution<> di(0, 0xff);
	random_device rd;
	for(int i=0; i<byte; i++) arr[i] = di(rd);
	auto z = nextprime(bnd2mpz(arr, arr+byte));//a little hole : over 0xffffffffffff
	for(int i=0; i<byte; i++) arr[i] = 0xff;
	if(z > bnd2mpz(arr, arr+byte)) return random_prime(byte);
	else return z;
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod) 
{
	mpz_class r;
	assert(mod);
	mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
	return r;
}

