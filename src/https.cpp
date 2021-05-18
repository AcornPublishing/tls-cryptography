#include"util/option.h"
#include"tls.h"
#include"https.h"
#include"util/log.h"
using namespace std;

int main(int ac, char** av) 
{
	CMDoption co{
		{"port", "listening port", 4433},
		{"inner port", "http host port", 2001},
		{"log filter", "log filter setting, use lower case to disable log", "tdIWEF"}
	};
	if(!co.args(ac, av)) return 0;
	Log::get_instance()->set_log_filter(co.get<const char*>("log filter"));
	Middle sv{co.get<int>("port"), co.get<int>("inner")};
	sv.start();
}


