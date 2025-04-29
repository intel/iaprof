default: iaprof

all: deps iaprof

iaprof:
	make -C src

deps:
	$(MAKE) -C deps

deps_clean:
	$(MAKE) -C deps clean

clean:
	$(MAKE) -C src clean

.PHONY: iaprof deps deps_clean clean
