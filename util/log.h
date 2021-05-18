#pragma once
#include<mutex>
#include<fstream>
#include<memory>
#include<iostream>
#define LOG (*Log::get_instance()<<Log::get_instance()->log_level()<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | ")
#define LOGT Log::get_instance()->set_log_level(Log::TRACE),*Log::get_instance()<<'T'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "
#define LOGD Log::get_instance()->set_log_level(Log::DEBUG),*Log::get_instance()<<'D'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "
#define LOGI Log::get_instance()->set_log_level(Log::INFO),*Log::get_instance()<<'I'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "
#define LOGW Log::get_instance()->set_log_level(Log::WARNING),*Log::get_instance()<<'W'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "
#define LOGE Log::get_instance()->set_log_level(Log::ERROR),*Log::get_instance()<<'E'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "
#define LOGF Log::get_instance()->set_log_level(Log::FATAL),*Log::get_instance()<<'F'<<Log::time()<<','<<__FILE__<<':'<<std::dec<<__LINE__<<','<<__func__<<" | "

class Log
{
public:
	static std::unique_ptr<Log>& get_instance();
	static std::string time();
	char log_level();
	template<class T> Log& operator<<(T r) {
		if(log_on_[log_level_]) {
			if(use_mutex_) mtx_.lock();
			std::cerr << r;
			log_file_ << r;
			if(use_mutex_) mtx_.unlock();
		}
		return *this;
	}
	Log& operator<<(std::ostream& (*manipulators)(std::ostream&));
	enum LogLevel { TRACE, DEBUG, INFO, WARNING, ERROR, FATAL } log_level_ = LogLevel::DEBUG;
	void set_log_level(LogLevel l);
	void set_log_filter(std::string filter);

protected:
	std::ofstream log_file_;
	std::mutex mtx_;
	bool use_mutex_ = false;
	bool log_on_[6] = {true, true, true, true, true, true};

private:
	static std::unique_ptr<Log> plog_;
	Log();
};
