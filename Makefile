default: iaprof

all: deps iaprof release

iaprof:
	make -C src

deps:
	$(MAKE) -C deps

deps_clean:
	$(MAKE) -C deps clean

release:
	./scripts/create_release.sh

clean:
	$(MAKE) -C src clean

.PHONY: iaprof deps deps_clean release clean
