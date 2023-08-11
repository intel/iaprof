CC      = /opt/intel/oneapi/compiler/latest/linux/bin/icpx
CFLAGS  = -Wall -O3 -ffast-math -march=native
LDFLAGS = -L/usr/lib/x86_64-linux-gnu/ -liga64

PLATFORM = $(shell uname -s)
ifeq ($(PLATFORM), Darwin)
	LDFLAGS = -framework OpenCL
else
	CFLAGS += -fopenmp
	LDFLAGS += -lOpenCL -lm
endif

# -------

EXE = bude

.PHONY: all $(EXE) clean

all: $(EXE)

$(EXE): bude.c
	$(CC) $(CFLAGS) bude.c $(LDFLAGS) -o $@

clean:
	rm -f $(EXE)
