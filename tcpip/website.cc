#include<fstream>
#include<sstream>
#include<cstring>
#include<iostream>
#include<experimental/filesystem>
#include<regex>
#include"server.h"
#include"website.h"
using namespace std;
using namespace std::experimental::filesystem;

map<string, string> WebSite::fileNhtml_;
WebSite::WebSite(string dir)
{
	for(const path& a : directory_iterator{dir}) {//directory entry has operator path
		ifstream f(a.string()); string s; char c;
		while(f >> noskipws >> c) s += c;
		fileNhtml_[a.filename()] = s;
		cout << "loading " << a.filename() << endl;
	}
}

bool WebSite::swap(string b, string a)
{//child classes will use this to change content_
	if(content_.find(b) == string::npos) return false;
	content_.replace(content_.find(b), b.size(), a);
	return true;	
}

bool WebSite::append(string a, string b)
{
	if(content_.find(a) == string::npos) return false;
	content_.insert(content_.find(a) + a.size(), b);
	return true;	
}

std::string WebSite::operator()(string s) 
{//will set requested_document and nameNvalue (= parameter of post or get)
	nameNvalue_.clear();
	stringstream ss; ss << s; ss >> s;
	if(s == "POST") {//parse request and header
		ss >> requested_document_;
		requested_document_ = requested_document_.substr(1);
		string boundary;
		while(s != "\r") {
			getline(ss, s);
			if(s.find("Content-Type: multipart/form-data;") == 0) {
				boundary = s.substr(s.find("boundary=") + 9);
				boundary.pop_back();
			}
		}
		if(boundary == "") nameNvalue_ = parse_post(ss);
		else parse_multi(ss, boundary);
	} else if(s == "GET") {
		ss >> s;
		stringstream ss2; ss2 << s;//GET '/login.html?adf=fdsa'
		getline(ss2, s, '?');
		requested_document_ = s.substr(1);//get rid of '/'
		nameNvalue_ = parse_post(ss2);
	}
	if(requested_document_ == "") requested_document_ = "index.html";
	content_ = fileNhtml_[requested_document_];
	try {
		process();//derived class should implement this -> set content_ & cookie
	} catch(const exception& e) {
		cerr << e.what() << endl;
	}
	return header_ + to_string(content_.size()) + "\r\n\r\n" + content_;
}

istream& WebSite::parse_one(istream& is, string boundary)
{
	regex e1{R"raw(name="(\w+)")raw"}, e2{R"raw(filename="(\S+)")raw"};
	smatch m; string s, name, filename, val;
	if(!getline(is, s)) return is;
	if(regex_search(s, m, e1)) name = m[1].str();
	s = m.suffix().str();
	if(regex_search(s, m, e2)) filename = m[1].str();
	do getline(is, s);//skip
	while(s != "\r");
	
	while(getline(is, s)) {//parse value
		if(s.find(boundary) != string::npos) break;
		val += s + '\n';
	}
	val.pop_back();// + \n
	val.pop_back();//\r
	nameNvalue_[name] = val;
	if(filename != "") nameNvalue_["filename"] = filename;
	return is;
}

void WebSite::parse_multi(istream& is, string boundary)
{
	string s;
	getline(is, s);
	while(parse_one(is, boundary));
}

map<string, string> WebSite::parse_post(istream& post)
{
	map<string, string> m;
	string s, value;
	while(getline(post, s, '&')) {
		int pos = s.find('=');
		value = s.substr(pos+1);
		for(auto& a : value) if(a == '+') a = ' ';
		for(int i = value.find('%'); i != string::npos; i = value.find('%', i))
			value.replace(i, 3, 1, (char)stoi(value.substr(i + 1, 2), nullptr,16));
		if(value.back() == '\0') value.pop_back();
		m[s.substr(0, pos)] = value;
	}
	return m;
}

