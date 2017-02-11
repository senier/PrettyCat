LDFLAGS += -lgcrypt

PROGS = dsagen dsasign dsasexp dsavrfy

PRIV := $(shell mktemp tmp-prv-XXXXX)
PUB  := $(shell mktemp tmp-pub-XXXXX)
SIG  := $(shell mktemp tmp-sig-XXXXX)
DATA := $(shell mktemp tmp-dat-XXXXX)

all: $(PROGS)

dsagen:  dsagen.o common.o
dsasign: dsasign.o common.o
dsasexp: dsasexp.o common.o
dsavrfy: dsavrfy.o common.o

clean:
	rm -f *.o $(PROGS) tmp-*

test: $(PROGS)
	./dsasexp "Thats a test" $(DATA)
	./dsagen $(PRIV) $(PUB)
	./dsasign $(PRIV) $(DATA) $(SIG)
	./dsavrfy $(PUB) $(DATA) $(SIG)
