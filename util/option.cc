#include<typeinfo>
#include<iostream>
#include"option.h"
using namespace std;

CMDoption::CMDoption(initializer_list<tuple<const char*, const char*, any>> options)
{
	options_ = options;
}

bool CMDoption::args(int ac, char **av)
{//return false if arguments are wrong
	any *val = nullptr;
	for(int i=1; i<ac; i++) {
		if(av[i][0] == '-') {
			int match=0;
			for(auto& [param, desc, value] : options_) {
				if(!strcmp(&av[i][1], param)) {//complete match
					match = 1;
					val = &value;
					break;
				} else if(!strncmp(&av[i][1], param, strlen(av[i])-1)){//partial match
					match++;
					val = &value;
				}
			}
			if(match != 1) return print_help(av[0]);
			else if(val->type() == typeid(bool)) *val = true;
		} else {
			if(!val) return print_help(av[0]);
			if(val->type() == typeid(int)) *val = atoi(av[i]);
			else if(val->type() == typeid(double) || val->type() == typeid(float))
				*val = atof(av[i]);
			else if(val->type() == typeid(const char*)) *val = (const char*)av[i];
			else if(val->type() == typeid(FileExpansion))
				*val = any_cast<FileExpansion>(*val) + av[i];
		}
	}
	return true;
}

bool CMDoption::print_help(char *av0)
{
	cout << "usage : " << av0 << " [options] [value]\n";
	cout << "you should use at least distinguishable amount of characters of options\nif default is boolean you don't need value\navailable options\n";
	for(auto& [pa, desc, val] : options_) {
		cout << '-' << pa << " : " << desc << "(default ";
		if(val.type() == typeid(int)) cout << any_cast<int>(val);
		else if(val.type() == typeid(double)) cout << any_cast<double>(val);
		else if(val.type() == typeid(float)) cout << any_cast<float>(val);
		else if(val.type() == typeid(const char*)) cout << any_cast<const char*>(val);
		else if(val.type() == typeid(bool)) cout << "false";
		else if(val.type() == typeid(FileExpansion)) cout << "none";
		cout << ")\n";
	}
	return false;
}
