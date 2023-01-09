all: airodump-ng

airodump-ng: airodump-ng.o
	gcc -o airodump-ng airodump-ng.o -lpcap -pthread
airodump-ng.o: main.h main.c
	gcc -c -o airodump-ng.o main.c -lpcap -pthread

clean:
	rm -f airodump-ng
	rm -f *.o
