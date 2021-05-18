#include<iostream>
#include"server.h"//Server class
#include"website.h"//WebSite class
#include"util/option.h"
using namespace std;

int main(int ac, char** av)
{
	CMDoption co{ {"port", "port of the host", 2001} };
	if(!co.args(ac, av)) return 0;
	WebSite my_site{"site_html"};//directory name relative to your exe file
							//directory contains html files
	Server sv{co.get<int>("port")};//port number
	cout << "opening port " << co.get<int>("port") << endl;
	sv.start(my_site);//go infinite loop
}

