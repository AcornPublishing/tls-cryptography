#include<cstring>
#include"hmac.h"

template<class H> struct HKDF : public HMAC<H>
{
	void zero_salt() {
		uint8_t zeros[H::output_size] = {0,};
		this->key(zeros, zeros + H::output_size);
	}
	void salt(uint8_t *p, int sz) {
		this->key(p, p + sz);
	}
	std::vector<uint8_t> extract(uint8_t *p, int sz) {
		auto a = this->hash(p, p + sz);
		return std::vector<uint8_t>{a.begin(), a.end()};
	}
	std::vector<uint8_t> derive_secret(std::string label, std::string msg) {
		auto a = this->sha_.hash(msg.begin(), msg.end());
		return expand_label(label, std::string{a.begin(), a.end()}, H::output_size);
	}
	std::vector<uint8_t> expand(std::string info, int L) {
		std::vector<uint8_t> r;
		int k = H::output_size + info.size() + 1;
		uint8_t t[k];
		memcpy(t + H::output_size, info.data(), info.size());
		t[k-1] = 1;
		auto a = this->hash(t + H::output_size, t + k);
		r.insert(r.end(), a.begin(), a.end());
		while(r.size() < L) {
			memcpy(t, &a[0], a.size());
			t[k-1]++;
			a = this->hash(t, t + k);
			r.insert(r.end(), a.begin(), a.end());
		}
		r.resize(L);
		return r;
	}
	std::vector<uint8_t> expand_label(std::string label, std::string context, int L) {
		std::string s = "xxxtls13 " + label + 'x' + context;
		s[0] = L / 0x100;
		s[1] = L % 0x100;
		s[2] = label.size() + 6;
		s[label.size() + 9] = context.size();
		return expand(s, L);
	}
};

