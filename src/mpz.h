#pragma once
#include<iomanip>
#include<sstream>
#include<gmpxx.h>

mpz_class random_prime(unsigned byte);
mpz_class nextprime(mpz_class n);
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);
template<typename It> void mpz2bnd(mpz_class n, It begin, It end)
{//mpz to big endian
	for(It i=end; i!=begin; n /= 0x100) *--i = mpz_class{n % 0x100}.get_ui();
}

template<class It> void mpz2bnd(int n, It begin, It end)
{
	for(It i=end; i!=begin; n /= 0x100) *--i = n % 0x100;
}

template<typename It> mpz_class bnd2mpz(It begin, It end)
{//big endian to mpz
	std::stringstream ss; ss << "0x";
	for(It i=begin; i!=end; i++)
		ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
	return mpz_class{ss.str()};
}
template<class C> std::string hexprint(const char *p, const C &c)
{//log container specialization
	std::stringstream ss;
	ss << p << " : 0x";
	for(unsigned char a : c) ss << std::hex << std::setw(2) << std::setfill('0')<< +a;
	return ss.str();
}
