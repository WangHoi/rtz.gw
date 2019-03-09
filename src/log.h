#pragma once

enum LogLevel {
	LL_FATAL,
	LL_ERROR,
	LL_WARN,
	LL_INFO,
	LL_DEBUG,
	LL_TRACE,
};

void llog_set_level(enum LogLevel lvl);
#define LLOG(lvl, fmt, ...) llog_fmt(__FILE__, __LINE__, __FUNCTION__, lvl, fmt, ##__VA_ARGS__)
void llog_fmt(const char* filename, int fileline, const char* funcname, enum LogLevel lvl,
	          const char* fmt, ...) __attribute__((format(printf, 5, 6)));

void llog_init(int console, const char *fname);
void llog_cleanup();
