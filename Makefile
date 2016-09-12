all: otr.svg

TESTS = $(wildcard tests/*.spg)
SPG_ARGS = --dump

otr.svg: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output $@

tests:: $(TESTS:.spg=.test)
	@echo "$(words $^) TESTS DONE."

tests/%.svg: tests/%.spg
	@echo "=== Graph $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@

tests/%.test: tests/%.spg
	@echo "=== Running $@"
	@./spg.py $(SPG_ARGS) --input $< --test
