#include<iomanip>
#include<cctype>
#include<chrono>
#include"log.h"
using namespace std;

unique_ptr<Log> Log::plog_ = nullptr;

unique_ptr<Log>& Log::get_instance()
{
	if(!plog_) plog_ = unique_ptr<Log>{new Log()};
	return plog_;
}

Log::Log() : log_file_{"/tmp/log", ios::app | ios::out}
{ }

Log& Log::operator<<(ostream& (*manipulators)(ostream&))
{
	if(log_on_[log_level_]) {
		if(use_mutex_) mtx_.lock();
		cerr << manipulators;
		log_file_ << manipulators;
		if(use_mutex_) mtx_.unlock();
	}
	return *this;
}

char Log::log_level()
{
	char c[] = "TDIWEF";
	return c[log_level_];
}

string Log::time()
{
	auto now = chrono::system_clock::now();
	auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) %1000;
	auto tt = chrono::system_clock::to_time_t(now);
	auto *bt = localtime(&tt);
	stringstream ss;
	ss << put_time(bt, "%T") <<'.'<< setfill('0') << setw(3) << ms.count();
	return ss.str();
}

void Log::set_log_level(LogLevel l)
{
	log_level_ = l;
}

void Log::set_log_filter(string keys)
{
	char k[] = "TDIWEF";
	for(char c : keys) for(int i=0; i<6; i++)
		if(c == k[i]) log_on_[i] = true;
		else if(c == tolower(k[i])) log_on_[i] = false;
}
