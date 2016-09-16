all: otr.svg

clean:
	rm -f otr.svg tests/*.svg

TESTS = $(wildcard tests/*.spg)
#SPG_ARGS = --dump

otr.svg: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output $@

tests:: $(TESTS:.spg=.svg)
	@echo "$(words $^) TESTS DONE."

tests/%.svg: tests/%.spg
	@echo "=== Graph $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@

tests/%.svg: tests/%.spg
	@echo "=== Running $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@ --test
