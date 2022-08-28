all: dns-export
dns-export: dns-export.cpp dns-export.h base64.cpp base64.h
	g++ -Wextra -g dns-export.cpp dns-export.h base64.cpp base64.h -std=c++11 -o dns-export -lpcap
clean:
	rm dns-export
