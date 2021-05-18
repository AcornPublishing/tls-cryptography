#pragma once
#include<cstring>
#include<vector>
#include<tuple>
#include<any>
#include<experimental/filesystem>

class CMDoption
{
public:
	CMDoption(std::initializer_list<std::tuple<const char*, const char*, std::any>> options);
	bool args(int ac, char **av);
	template<class T> T get(const char* param) {
		for(const auto& [pa, desc, value] : options_)
			if(!strncmp(pa, param, strlen(param))) return std::any_cast<T>(value);
	}

protected:
	std::vector<std::tuple<const char*, const char*, std::any>> options_;
	//					   parameter	description	 default value
	
private:
	bool print_help(char *av0);
};

class FileExpansion
{//for *.jpg
public:
	FileExpansion& operator+(const char* r) {
		v.push_back(r);
		return *this;
	}
	auto begin() { return v.begin(); }
	auto end() { return v.end(); }
protected:
	std::vector<std::experimental::filesystem::path> v;
};
