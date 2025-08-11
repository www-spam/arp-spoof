LDLIBS = -lpcap
CXXFLAGS ?= -std=c++17 -O2 -Wall

all: arp-spoof

arp-spoof.o: arp-spoof.h arp-spoof.cpp

arp-spoof: arp-spoof.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
