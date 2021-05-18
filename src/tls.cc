#include<cstring>
#include<fstream>
#include"util/log.h"
#include"mpz.h"
#include"sha256.h"
#include"cert_util.h"
#include"prf.h"
#include"tls.h"
using namespace std;

mpz_class get_prvkey(istream& is);

//static member initialization
static mpz_class ze, zd, zK;//used in TLS constructor

static string init_certificate()
{//this will run before main -> use for initialization
	ifstream f2("key.pem");//generated with openssl genrsa 2048 > key.pem
	ifstream f("cert.pem");//openssl req -x509 -days 1000 -new -key key.pem -out cert.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;

	vector<unsigned char> r;
	for(string s; (s = get_certificate_core(f)) != "";) {
		auto v = base64_decode(s);
		for(int i=0; i<3; i++) r.push_back(0);
		mpz2bnd(v.size(), r.end() - 3, r.end());
		r.insert(r.end(), v.begin(), v.end());
	}
	vector<uint8_t> v = {HANDSHAKE, 3, 3, 0, 0, CERTIFICATE, 0, 0, 0, 0, 0, 0};
	mpz2bnd(r.size(), v.end() - 3, v.end());
	mpz2bnd(r.size() + 3, v.end() - 6, v.end() - 3);
	mpz2bnd(r.size() + 7, v.begin() + 3, v.begin() + 5);
	r.insert(r.begin(), v.begin(), v.end());
	return {r.begin(), r.end()};
}

template<bool SV> string TLS<SV>::certificate_ = init_certificate();
template<bool SV> RSA TLS<SV>::rsa_{ze, zd, zK};
template class TLS<true>;//server
template class TLS<false>;//client

template<bool SV> pair<int, int> TLS<SV>::get_content_type(const string &s)
{
	uint8_t *p = (uint8_t*)s.data();
	return {p[0], p[5]};
}

template<bool SV>
void TLS<SV>::generate_signature(unsigned char* pub_key, unsigned char* sign)
{
	unsigned char a[64 + 69];
	memcpy(a, client_random_.data(), 32);
	memcpy(a + 32, server_random_.data(), 32);
	memcpy(a + 64, pub_key, 69);
	SHA2 sha;
	auto b = sha.hash(a, a + 64 + 69);
	std::deque<unsigned char> dq{b.begin(), b.end()};
	dq.push_front(dq.size());
	unsigned char d[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04};//01 : sha2, if -> 03 : sha5 
	dq.insert(dq.begin(), d, d + 16);
	dq.push_front(dq.size());
	dq.push_front(0x30);
	dq.push_front(0x00);
	while(dq.size() < 254) dq.push_front(0xff);
	dq.push_front(0x01);
	dq.push_front(0x00);
	auto z = rsa_.sign(bnd2mpz(dq.begin(), dq.end()));//SIGPE
	mpz2bnd(z, sign, sign + 256);
}

template<bool SV>
void TLS<SV>::derive_keys(mpz_class premaster_secret)
{//K distribution OK, master secret derivation err
	unsigned char pre[32], rand[64];
	mpz2bnd(premaster_secret, pre, pre + 32);
	PRF<SHA2> prf;
	prf.secret(pre, pre + 32);
	memcpy(rand, client_random_.data(), 32);
	memcpy(rand + 32, server_random_.data(), 32);
	LOGD << hexprint("pre", pre) << endl;
	LOGD << hexprint("server random", server_random_) << endl;
	LOGD << hexprint("client random", client_random_) << endl;
	prf.seed(rand, rand + 64);
	prf.label("master secret");
	master_secret_ = prf.get_n_byte(48);
	LOGD << hexprint("master secret", master_secret_) << endl;//ok
	prf.secret(master_secret_.begin(), master_secret_.end());
	memcpy(rand, server_random_.data(), 32);
	memcpy(rand + 32, client_random_.data(), 32);
	prf.seed(rand, rand + 64);
	LOGD << hexprint("server random", server_random_) << endl;
	LOGD << hexprint("client random", client_random_) << endl;
	prf.label("key expansion");
	auto v = prf.get_n_byte(40);
	aes_[0].key(&v[0]);
	aes_[1].key(&v[16]);
	aes_[0].iv(&v[32], 0, 4);
	aes_[1].iv(&v[36], 0, 4);
	LOGD << hexprint("expanded keys", v) << endl;//different client, server
}

#pragma pack(1)
struct TLS_header {
	uint8_t content_type = HANDSHAKE;  // 0x17 for Application Data, 0x16 handshake
	uint8_t version[2] = {0x03, 0x03};      // 0x0303 for TLS 1.2
	uint8_t length[2] = {0, 4};       //length of encrypted_data, 4 : handshake size
	void set_length(int k) { length[0] = k / 0x100; length[1] = k % 0x100; }
	int get_length() { return length[0] * 0x100 + length[1]; }
} ;

struct Handshake_header {
	uint8_t handshake_type;
	uint8_t length[3] = {0,0,0};
	void set_length(int k) {
		length[0] = k / 0x10000;
		length[1] = (k % 0x10000) / 0x100;
		length[2] = k % 0x100;
	}
	int get_length() { return length[0] * 0x10000 + length[1] * 0x100 + length[0]; }
} ;

struct Hello_header {
	uint8_t version[2] = {0x03, 0x03};//length is from here
	uint8_t random[32];
	uint8_t session_id_length = 32;//can be 0
	uint8_t session_id[32];
};

template<bool SV> string TLS<SV>::accumulate(const string &s)
{
	accumulated_handshakes_ += s.substr(sizeof(TLS_header));
	return s;
}

template<bool SV> string TLS<SV>::client_hello(string&& s)
{//return desired id
	struct H {
		TLS_header h1;
		Handshake_header h2;
		Hello_header h3;
		uint8_t cipher_suite_length[2] = {0, 2};
		uint8_t cipher_suite[2] = {0xc0, 0x2f};//ECDHE RSA AES128 GCM SHA256
		uint8_t compression_length = 1;
		uint8_t compression_method = 0;//none
	} r;
	if constexpr(!SV) {//if client
		r.h2.handshake_type = CLIENT_HELLO;
		r.h1.set_length(sizeof(r) - sizeof(TLS_header));
		r.h2.set_length(sizeof(r) - sizeof(TLS_header) - sizeof(Handshake_header));
		mpz2bnd(random_prime(32), r.h3.random, r.h3.random + 32);
		memcpy(client_random_.data(), r.h3.random, 32);//unix time + 28 random
		return accumulate(struct2str(r));
	} else {//server
		if(get_content_type(s) != pair{HANDSHAKE, CLIENT_HELLO}) return alert(2, 10);
		accumulate(s);
		H *p = (H*)s.data();
		memcpy(client_random_.data(), p->h3.random, 32);//unix time + 28 random
		unsigned char *q = &p->h3.session_id_length;
		q += *q + 1;
		int len = *q++ * 0x100 + *q++;
		for(int i=0; i<len; i+=2) if(*(q+i) == 0xc0 && *(q+i+1) == 0x2f) return "";
		return alert(2, 40);
	}
}

template<bool SV> string TLS<SV>::server_hello(string &&s)
{
	struct H {
		TLS_header h1;
		Handshake_header h2;
		Hello_header h3;
		uint8_t cipher_suite[2] = {0xc0, 0x2f};
		uint8_t compression = 0;
		//uint8_t extension_length[2] = {0, 0};
	} r;
	if constexpr(SV) {
		r.h1.length[1] = sizeof(Hello_header) + sizeof(Handshake_header) + 3;
		r.h2.length[2] = sizeof(Hello_header) + 3;
		r.h2.handshake_type = SERVER_HELLO;
		mpz2bnd(random_prime(32), server_random_.begin(), server_random_.end());
		mpz2bnd(random_prime(32), session_id_.begin(), session_id_.end());
		memcpy(r.h3.random, server_random_.data(), 32);
		memcpy(r.h3.session_id, session_id_.data(), 32);
		return accumulate(struct2str(r));
	} else {
		if(get_content_type(s) != pair{HANDSHAKE, SERVER_HELLO}) 
			return alert(2, 10);
		accumulate(s);
		H *p = (H*)s.data();
		memcpy(server_random_.data(), p->h3.random, 32);
		memcpy(session_id_.data(), p->h3.session_id, 32);
		if(p->cipher_suite[0] == 0xc0 && p->cipher_suite[1] == 0x2f) return "";
		else return alert(2, 40);
	}
}

template<bool SV> string TLS<SV>::server_certificate(string&& s)
{
	if constexpr(SV) return accumulate(certificate_);
	else {
		if(get_content_type(s) != pair{HANDSHAKE, CERTIFICATE}) 
			return alert(2, 10);
		accumulate(s);
		struct H {
			TLS_header h1;
			Handshake_header h2;
			uint8_t certificate_length[2][3];//total len + first cert len
			unsigned char certificate[];//first cert
		} *p = (H*)s.data();
		std::stringstream ss;
		uint8_t *q = p->certificate_length[1];
		for(int i=0, j = *q * 0x10000 + *(q+1) * 0x100 + *(q+2); i < j; i++) 
			ss << noskipws << p->certificate[i];//first certificate
		Json::Value jv;
		try {
			jv = der2json(ss);
		} catch(const char *e) {
			cerr << "certificate error : " << e << '\n';
			return alert(2, 44);
		}
		auto [K, e, sign] = get_pubkeys(jv);

		LOGD << "K : " << K << endl;
		LOGD << "e : " << e << endl;
		LOGD << hex << "sign : " << sign << endl;
		rsa_.K = K; rsa_.e = e;
		return "";
	}
}

template<bool SV> string TLS<SV>::server_key_exchange(string&& s)
{
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t named_curve = 3,
				secp256r[2] = {0, 0x17},
				key_length = 65,
				uncommpressed = 4,
				x[32], y[32];
		uint8_t signature_hash = 4, //SHA256
				signature_sign = 1, //rsa
				signature_length[2] = {1, 0}, sign[256];
		/*enum { none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255) } HashAlgorithm;
		  enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;*/
	} r;

	if constexpr(SV) {
		r.h1.set_length(sizeof(r) - sizeof(TLS_header));
		r.h2.set_length(sizeof(r) - sizeof(TLS_header) - sizeof(Handshake_header));
		r.h2.handshake_type = SERVER_KEY_EXCHANGE;
		mpz2bnd(P_.x, r.x, r.x+32);
		mpz2bnd(P_.y, r.y, r.y+32);
		generate_signature(&r.named_curve, r.sign);
		return accumulate(struct2str(r));
	} else {
		if(get_content_type(s) != pair{HANDSHAKE, SERVER_KEY_EXCHANGE})
			return alert(2, 10);
		accumulate(s);
		const H *p = reinterpret_cast<const H*>(s.data());
		EC_Point Y{bnd2mpz(p->x, p->x+32), bnd2mpz(p->y, p->y+32), secp256r1_};
		derive_keys((Y * prv_key_).x);

		//check signature integrity
		auto z = rsa_.encode(bnd2mpz(p->sign, p->sign + 256));
		mpz2bnd(z, r.sign, r.sign+256);
		memcpy(r.sign, client_random_.data(), 32);
		memcpy(r.sign+32, server_random_.data(), 32);
		memcpy(r.sign+64, &p->named_curve, 69);
		SHA2 sha;
		auto a = sha.hash(r.sign, r.sign + 64 + 69);
		if(equal(r.sign + 224, r.sign + 256, a.begin())) return "";
		else return alert(2, 51);
	}	
}

template<bool SV> string TLS<SV>::server_hello_done(string&& s)
{
	struct {
		TLS_header h1;
		Handshake_header h2;
	} r;
	if constexpr(SV) {
		r.h2.handshake_type = SERVER_DONE;
		return accumulate(struct2str(r));
	} else {
		if(get_content_type(s) != pair{HANDSHAKE, SERVER_DONE}) return alert(2,10);
		accumulate(s);
		return "";
	}
}

template<bool SV> string TLS<SV>::change_cipher_spec(string &&s)
{
	struct {
		TLS_header h1;
		uint8_t spec = 1;
	} r;
	r.h1.content_type = CHANGE_CIPHER_SPEC;
	r.h1.length[1] = 1;
	return s == "" ? struct2str(r) : 
		(get_content_type(s).first == CHANGE_CIPHER_SPEC ? "" : alert(2, 10));
}

template<bool SV> string TLS<SV>::client_key_exchange(string&& s)//16
{//return client_aes_key + server_aes_key
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t len = 65;
		uint8_t uncommpressed = 4;
		uint8_t x[32], y[32];
	} r;

	if constexpr(SV) {
		if(get_content_type(s) != pair{HANDSHAKE, CLIENT_KEY_EXCHANGE}) 
			return alert(2, 10);
		accumulate(s);
		H* p = (H*)s.data();
		EC_Point Y{bnd2mpz(p->x, p->x+32), bnd2mpz(p->y, p->y+32), secp256r1_};
		derive_keys((Y * prv_key_).x);
		return "";
	} else {
		r.h2.handshake_type = 16;
		r.h1.set_length(sizeof(H) - sizeof(TLS_header));
		r.h2.set_length(sizeof(H) - sizeof(TLS_header) - sizeof(Handshake_header));
		mpz2bnd(P_.x, r.x, r.x+32);
		mpz2bnd(P_.y, r.y, r.y+32);
		return accumulate(struct2str(r)); 
	}
}

template<bool SV> optional<string> TLS<SV>::decode(string &&s)
{
	struct H {
		TLS_header h1;
		uint8_t iv[8];
		unsigned char m[];
	} *p = (H*)s.data();
	struct {
		uint8_t seq[8];
		TLS_header h1;
	} header_for_mac;

	LOGD << hexprint("decoding", s) << endl;

	if(int type = get_content_type(s).first; type != HANDSHAKE && type != APPLICATION_DATA)
		return {};//alert case
	mpz2bnd(dec_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);
	header_for_mac.h1 = p->h1;
	int msg_len = p->h1.get_length() - sizeof(H::iv) - 16;//tag length 16
	header_for_mac.h1.set_length(msg_len);
	uint8_t *aad = (uint8_t*)&header_for_mac;
	aes_[!SV].aad(aad, sizeof(header_for_mac));
	aes_[!SV].iv(p->iv, 4, 8);
	auto auth = aes_[!SV].decrypt(p->m, msg_len);//here key value is changed(the other key?)
	LOGD << hexprint("calculated auth", auth) << endl;
	LOGD << hexprint("attached auth", vector<unsigned char>{p->m + msg_len, p->m + msg_len + 16}) << endl;
	LOGD << "decoded : " << p->m << endl;
	if(equal(auth.begin(), auth.end(), p->m + msg_len)) return string{p->m, p->m + msg_len};
	else return {};//bad record mac
}

template<bool SV> string TLS<SV>::encode(string &&s, int type)
{
	struct {
		TLS_header h1;
		uint8_t iv[8];
	} header_to_send;
	struct {
		uint8_t seq[8];
		TLS_header h1;
	} header_for_mac;
	header_for_mac.h1.content_type = header_to_send.h1.content_type = type;

	mpz2bnd(enc_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);
	const size_t chunk_size = (1 << 14) - 64;//cut string into 2^14
	int len = min(s.size(), chunk_size);
	header_for_mac.h1.set_length(len);
	string frag = s.substr(0, len);

	mpz2bnd(random_prime(8), header_to_send.iv, header_to_send.iv + 8);
	aes_[SV].iv(header_to_send.iv, 4, 8);
	uint8_t *aad = (uint8_t*)&header_for_mac;
	aes_[SV].aad(aad, sizeof(header_for_mac));
	auto tag = aes_[SV].encrypt(reinterpret_cast<unsigned char*>(&frag[0]), frag.size());
	LOGD << hexprint("auth tag", tag) << endl;
	frag += string{tag.begin(), tag.end()};
	header_to_send.h1.set_length(sizeof(header_to_send.iv) + frag.size());
	string s2 = struct2str(header_to_send) + frag;
	LOGD << hexprint("sending", s2) << endl;
	if(s.size() > chunk_size) s2 += encode(s.substr(chunk_size));
	return s2;
}

template<bool SV> string TLS<SV>::finished(string &&s)
{//finished message to send(s == "") and receive(s == recv())
	PRF<SHA2> prf; SHA2 sha;
	prf.secret(master_secret_.begin(), master_secret_.end());
	auto h = sha.hash(accumulated_handshakes_.cbegin(), accumulated_handshakes_.cend());
	prf.seed(h.begin(), h.end());
	const char *label[2] = {"client finished", "server finished"};
	prf.label(label[s == "" ? SV : !SV]);
	auto v = prf.get_n_byte(12);
	LOGD << hexprint("finished", v) << endl;

	Handshake_header hh;
	hh.handshake_type = FINISHED;
	hh.set_length(12);
	
	string msg = struct2str(hh) + string{v.begin(), v.end()};
	accumulated_handshakes_ += msg;
	
	if(s == "") return encode(move(msg), HANDSHAKE);
	else if(decode(move(s)) != msg) return alert(2, 51);
	else return "";
}

template<bool SV> string TLS<SV>::alert(uint8_t level, uint8_t desc)
{//encrypted send => encode(alert(2, 20).substr(sizeof(TLS_header)), 0x15)
	struct {
		TLS_header h1;
		uint8_t alert_level;
		uint8_t alert_desc;
	} h;
	h.h1.content_type = ALERT;
	h.alert_level = level;
	h.alert_desc = desc;
	h.h1.set_length(2);
	return struct2str(h);
}
template<bool SV> int TLS<SV>::alert(string &&s)
{//alert received
	struct H {
		TLS_header h1;
		uint8_t alert_level;
		uint8_t alert_desc;
	} *p = (H*)s.data();
	int level, desc;
	if(p->h1.get_length() == 2) {
		level = p->alert_level;
		desc = p->alert_desc;
	} else {//encrypted
		s = *decode(move(s));
		level = static_cast<uint8_t>(s[0]);
		desc = static_cast<uint8_t>(s[1]);
	}
	switch(desc) {//s reuse
		case 0: s = "close_notify(0)"; break;
		case 10: s = "unexpected_message(10)"; break;
		case 20: s = "bad_record_mac(20)"; break;
		case 21: s = "decryption_failed_RESERVED(21)"; break;
		case 22: s = "record_overflow(22)"; break;
		case 30: s = "decompression_failure(30)"; break;
		case 40: s = "handshake_failure(40)"; break;
		case 41: s = "no_certificate_RESERVED(41)"; break;
		case 42: s = "bad_certificate(42)"; break;
		case 43: s = "unsupported_certificate(43)"; break;
		case 44: s = "certificate_revoked(44)"; break;
		case 45: s = "certificate_expired(45)"; break;
		case 46: s = "certificate_unknown(46)"; break;
		case 47: s = "illegal_parameter(47)"; break;
		case 48: s = "unknown_ca(48)"; break;
		case 49: s = "access_denied(49)"; break;
		case 50: s = "decode_error(50)"; break;
		case 51: s = "decrypt_error(51)"; break;
		case 60: s = "export_restriction_RESERVED(60)"; break;
		case 70: s = "protocol_version(70)"; break;
		case 71: s = "insufficient_security(71)"; break;
		case 80: s = "internal_error(80)"; break;
		case 90: s = "user_canceled(90)"; break;
		case 100: s = "no_renegotiation(100)"; break;
		case 110: s = "unsupported_extension(110)"; break;
	}
	if(level == 1) LOGI << s << endl;
	else if(level == 2) LOGI << s << endl;
	return desc;
}
#pragma pack()
