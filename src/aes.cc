#include<algorithm>
#include"aes.h"
using namespace std;

template class CBC<AES>;
template class GCM<AES>;
template class CipherMode<AES>;

static unsigned char doub(unsigned char c)
{
	bool left_most_bit = c & 1 << 7;
	c <<= 1;
	if(left_most_bit) c ^= 0x1b;
	return c;
}

int initialize_precomputed()
{
	for(int i=0; i<256; i++) AES::precomputed[0][i] = doub(doub(doub(i))) ^ i;
	for(int i=0; i<256; i++) AES::precomputed[1][i] = doub(doub(doub(i)) ^ i) ^ i;
	for(int i=0; i<256; i++) AES::precomputed[2][i] = doub(doub(doub(i) ^ i)) ^ i;
	for(int i=0; i<256; i++) AES::precomputed[3][i] = doub(doub(doub(i) ^ i) ^ i);
	return 0;
}

uint8_t AES::precomputed[4][256];
static int garbage_int_to_execute_init = initialize_precomputed();

void AES::key(const unsigned char *pkey) {
	memcpy(schedule_[0], pkey, 16);
	unsigned char *p = &schedule_[1][0];
	for(int i=1; i<ROUND; i++) {
		for(int j=0; j<3; j++) *(p+j) = *(p+j-3);
		*(p+3) = *(p-4);
		for(int j=0; j<4; j++) *(p+j) = sbox[*(p+j)];
		for(int j=0; j<4; j++, p++) {//p+=4
			*p ^= rcon[4*i/N-1][j];
			*p ^= *(p - 4*N);
		}
		for(int j=0; j<12; j++, p++) *p = *(p - 4*N) ^ *(p - 4);//p+=12
	}
}

void AES::encrypt(unsigned char *m) const
{
	add_round_key(m, 0);
	for(int round=1; round<ROUND-1; round++) {
		substitute(m);
		shift_row(m);
		mix_column(m);
		add_round_key(m, round);
	}
	substitute(m);
	shift_row(m);
	add_round_key(m, ROUND-1);
}

void AES::decrypt(unsigned char *p) const
{
	add_round_key(p, ROUND-1);
	for(int round=ROUND-2; round>0; round--) {
		inv_shift_row(p);
		inv_substitute(p);
		add_round_key(p, round);
		inv_mix_column(p);
	}
	inv_shift_row(p);
	inv_substitute(p);
	add_round_key(p, 0);
}

void AES::substitute(unsigned char *p) const
{
	for(int i=0; i<16; i++) p[i] = sbox[p[i]];
}

void AES::inv_substitute(unsigned char *p) const
{
	for(int i=0; i<16; i++) p[i] = inv_sbox[p[i]];
}

void AES::shift_row(unsigned char *p) const
{
	unsigned char tmp, tmp2;
	tmp = p[1]; p[1] = p[5]; p[5] = p[9]; p[9] = p[13]; p[13] = tmp;
	tmp = p[2]; tmp2 = p[6]; p[2] = p[10]; p[6] = p[14]; p[10] = tmp; p[14] = tmp2;
	tmp = p[3]; p[3] = p[15]; p[15] = p[11]; p[11] = p[7]; p[7] = tmp;
}

void AES::inv_shift_row(unsigned char *p) const
{
	unsigned char tmp, tmp2;
	tmp = p[13]; p[13] = p[9]; p[9] = p[5]; p[5] = p[1]; p[1] = tmp;
	tmp = p[10]; tmp2 = p[14]; p[14] = p[6]; p[10] = p[2]; p[6] = tmp2; p[2] = tmp;
	tmp = p[7]; p[7] = p[11]; p[11] = p[15]; p[15] = p[3]; p[3] = tmp;
}

void AES::mix_column(unsigned char *p) const
{
	static const unsigned char mix[4][4] 
		= {{2,3,1,1}, {1,2,3,1}, {1,1,2,3}, {3,1,1,2}};
	unsigned char c[4], d, result[16];
	for(int y=0; y<4; y++) for(int x=0; x<4; x++) {
		for(int i=0; i<4; i++) {
			d = p[4*x + i];
			switch(mix[y][i]) {
				case 1: c[i] = d; 			break;
				case 2: c[i] = d << 1;	 	break;
				case 3: c[i] = d << 1 ^ d;	break;
			}
			if((d & 1<<7) && (mix[y][i] != 1)) c[i] ^= 0x1b;//결합법칙덕분
		}
		result[4*x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
	}
	memcpy(p, result, 16);
}

void AES::inv_mix_column(unsigned char *p) const
{
	static const unsigned char mix[4][4] = {
		{14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}};
	unsigned char c[4], d, result[16];
	for(int y=0; y<4; y++) for(int x=0; x<4; x++) {
		for(int i=0; i<4; i++) {
			switch(mix[y][i]) {
				case 9: c[i] = precomputed[0][p[4*x + i]]; 	break;
				case 11: c[i] = precomputed[1][p[4*x + i]];	break;
				case 13: c[i] = precomputed[2][p[4*x + i]];	break;
				case 14: c[i] = precomputed[3][p[4*x + i]];	break;
			}
		}
		result[4*x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
	}
	memcpy(p, result, 16);
}

void AES::add_round_key(unsigned char *p, int k) const
{
	for(int i=0; i<16; i++) p[i] ^= schedule_[k][i];
}

template<class Cipher> void CipherMode<Cipher>::key(const unsigned char *p)
{
	cipher_.key(p);
}

template<class Cipher> void CBC<Cipher>::iv(const unsigned char *p)
{
	memcpy(this->iv_, p, 16);
}

template<class Cipher> void CBC<Cipher>::encrypt(unsigned char *p, int sz) const
{//sequencial
	assert(sz % 16 == 0);
	for(int i=0; i<16; i++) p[i] ^= this->iv_[i];
	for(int j=1; j<sz/16; j++) {
		this->cipher_.encrypt(p);
		for(int i=0; i<16; i++, p++) *(p + 16) ^= *p;//p+=16
	}
	this->cipher_.encrypt(p);
}

template<class Cipher> void CBC<Cipher>::decrypt(unsigned char *p, int sz) const
{//can be serialized
	assert(sz % 16 == 0);
	unsigned char buf[sz];
	memcpy(buf, p, sz);
	for(int i=0; i<sz; i+=16) this->cipher_.decrypt(p+i);
	for(int i=0; i<16; i++) *p++ ^= this->iv_[i];//p+=16
	for(int i=0; i<sz-16; i++) *p++ ^= buf[i];
}

template<class Cipher> void GCM<Cipher>::iv(const unsigned char *p)
{
	memcpy(this->iv_, p, 12);
}

template<class Cipher> void GCM<Cipher>::iv(const unsigned char *p, int from, int sz) 
{
	memcpy(this->iv_ + from, p, sz);
}

void doub(unsigned char *p) {
	bool bit1 = p[15] & 1;
	for(int i=15; i>0; i--) p[i] = (p[i] >> 1) | (p[i-1] << 7) ;
	p[0] >>= 1;
	if(bit1) p[0] ^= 0b11100001;
}

void gf_mul(unsigned char *x, unsigned char *y)
{//x = x * y
	unsigned char z[16] = {0,};
	for(int i=0; i<16; i++) {
		for(int j=0; j<8; j++) {//left most bit is 0 order
			if(y[i] & 1<<(7-j)) for(int k=0; k<16; k++) z[k] ^= x[k];
			doub(x);
		}
	}
	memcpy(x, z, 16);
//	cout << hexprint("aad", z) << endl;
}

template<class Cipher>
array<unsigned char, 16> GCM<Cipher>::encrypt(unsigned char *p, int sz)
{
	for(int i=0; i<sz; i+=16) xor_with_enc_ivNcounter(p + i, min(16, sz-i), i/16 + 2);
	return generate_auth(p, sz);
}

template<class Cipher> 
array<unsigned char, 16> GCM<Cipher>::generate_auth(unsigned char *p, int sz) {
	unsigned char H[16]={0,};
	array<unsigned char, 16> Auth;
	this->cipher_.encrypt(H);
	if(!aad_.empty()) {
		gf_mul(&aad_[0], H);
		for(int i=0; i<aad_.size()-16; i+=16) {//aad process
			for(int j=0; j<16; j++) aad_[i+16+j] ^= aad_[i+j];
			gf_mul(&aad_[i+16], H);
		}
		copy(aad_.end() - 16, aad_.end(), Auth.begin());
	}
	for(int i=0; i<sz; i+=16) {
		for(int j=0; j<min(16, sz-i); j++) Auth[j] ^= p[i+j];
		gf_mul(&Auth[0], H);
	}
	
	mpz2bnd(sz * 8, lenAC_ + 8, lenAC_ + 16);
	for(int i=0; i<16; i++) Auth[i] ^= lenAC_[i];
	gf_mul(&Auth[0], H);
	xor_with_enc_ivNcounter(&Auth[0], 16, 1);
	return Auth;
}

template<class Cipher>
void GCM<Cipher>::xor_with_enc_ivNcounter(unsigned char *p, int sz, int ctr)
{
	unsigned char ivNcounter[16];
	memcpy(ivNcounter, this->iv_, 12);
	mpz2bnd(ctr, ivNcounter + 12, ivNcounter + 16);
	this->cipher_.encrypt(ivNcounter);
	for(int i=0; i<sz; i++) p[i] ^= ivNcounter[i];
}

template<class Cipher>
array<unsigned char, 16> GCM<Cipher>::decrypt(unsigned char *p, int sz) 
{
	auto a = generate_auth(p, sz);
	for(int i=0; i<sz; i+=16) xor_with_enc_ivNcounter(p + i, min(16, sz-i), i/16 + 2);
	return a;
}

template<class Cipher> void GCM<Cipher>::xor_with_iv(const unsigned char *p) 
{
	for(int i=0; i<4; i++) this->iv_[i] ^= 0;
	for(int i=0; i<8; i++) this->iv_[4 + i] ^= p[i];
}

template<class Cipher> void GCM<Cipher>::aad(const unsigned char *p, int sz)
{
	aad_ = vector<uint8_t>{p, p+sz};
	mpz2bnd(aad_.size() * 8, lenAC_, lenAC_ + 8);
	while(aad_.size() % 16) aad_.push_back(0);
}
