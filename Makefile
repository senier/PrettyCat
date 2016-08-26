all: otr.svg

TESTS = $(wildcard tests/*.spg)

otr.svg: models/OTRrev3.spg spg.py
	./spg.py --input $< --output $@

tests:: $(TESTS:.spg=.test)
	@echo "$(words $^) TESTS DONE."

tests/%.test: tests/%.spg
	@echo "=== Running $@"
	@./spg.py --input $< --test
