
all: log

log: analyzer.cpp  analyzer.h main.cpp
	g++ $^ `mysql_config --cflags --libs` -o $@

.PHONY: all
