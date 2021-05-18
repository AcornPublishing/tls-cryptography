#pragma once
#include<array>
#include"hmac.h"

template<class H> class PRF
{//H is hash function usually sha256
public:
	template<class It> void secret(const It begin, const It end) {
		hmac_.key(begin, end);
	}
	void label(const char* p) {
		label_.clear();
		while(*p) label_.push_back(*p++);
	}
	template<class It> void seed(const It begin, const It end) {
		seed_.clear();
		for(It it = begin; it != end; it++) seed_.push_back(*it);
	}
	std::vector<unsigned char> get_n_byte(int n) {
		auto seed = label_;//seed = label + seed_
		seed.insert(seed.end(), seed_.begin(), seed_.end());
		std::vector<unsigned char> r, v;
		std::vector<std::array<unsigned char, H::output_size>> vA;
		vA.push_back(hmac_.hash(seed.begin(), seed.end()));//A(1)
		while(r.size() < n) {
			v.clear();
			v.insert(v.end(), vA.back().begin(), vA.back().end());
			v.insert(v.end(), seed.begin(), seed.end());
			auto h = hmac_.hash(v.begin(), v.end());
			r.insert(r.end(), h.begin(), h.end());
			vA.push_back(hmac_.hash(vA.back().begin(), vA.back().end()));//A(i+1)
		}
		r.resize(n);
		return r;
	}
	std::vector<unsigned char> get_n_byte2(int n) {
		auto seed = label_;//seed = label + seed_
		seed.insert(seed.end(), seed_.begin(), seed_.end());
		std::vector<unsigned char> r, v;
		for(auto A = hmac_.hash(seed.begin(), seed.end()); r.size() < n; 
				A = hmac_.hash(A.begin(), A.end()), v.clear()) {//A(i+1)
			v.insert(v.end(), A.begin(), A.end());
			v.insert(v.end(), seed.begin(), seed.end());
			auto h = hmac_.hash(v.begin(), v.end());
			r.insert(r.end(), h.begin(), h.end());
		}
		r.resize(n);
		return r;
	}

protected:
	HMAC<H> hmac_;
	std::vector<unsigned char> label_, seed_;
};

