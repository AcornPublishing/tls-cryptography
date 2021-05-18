#include<utility>
#include"diffie.h"

class ECDSA : public EC_Point
{
public:
	ECDSA(const EC_Point &G, mpz_class n);//for signature
	std::pair<mpz_class, mpz_class> sign(mpz_class m, mpz_class d) const;
	bool verify(mpz_class m, std::pair<mpz_class, mpz_class> sig, EC_Point Q) const;
	mpz_class mod_inv(const mpz_class &z) const;
protected:
	mpz_class n_;//{"0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"};
private:
	int nBit_;
	mpz_class d_;
};

