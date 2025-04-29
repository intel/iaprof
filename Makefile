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

save_config:
	$(MAKE) -C src save_config

.PHONY: iaprof deps deps_clean clean save_config
