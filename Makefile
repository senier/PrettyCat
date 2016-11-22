all: otr.svg

clean:
	rm -f otr.svg tests/*.svg tests/*.run *.graph TEMP_*
	rm -rf __pycache__

TESTS = $(wildcard tests/*.spg)
RUNS  = $(wildcard tests/run_*.spg)

#SPG_ARGS = --dump

otr.svg: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output TEMP_$@
	mv TEMP_$@ $@

otr.json: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output TEMP_$@
	mv TEMP_$@ $@

otr.dot: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output TEMP_$@
	mv TEMP_$@ $@

otr.run: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output TEMP_$@ --run
	mv TEMP_$@ $@

otr.graph: models/OTRrev3.spg spg.py
	./spg.py $(SPG_ARGS) --input $< --output TEMP_$@
	mv TEMP_$@ $@

tests:: $(sort $(TESTS:.spg=.svg)) $(sort $(RUNS:.spg=.run))
	@echo "$(words $^) TESTS DONE."

tests/%.svg: tests/%.spg spg.py
	@echo "=== Graph $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@

tests/%.svg: tests/%.spg spg.py
	@echo "=== Testing $<"
	-@./spg.py $(SPG_ARGS) --input $< --output tests/$*.FAILED.svg --test
	-@mv tests/$*.FAILED.svg $@

tests/%.run: tests/%.spg spg.py
	@echo "=== Running $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@.svg --run
	@mv $@.svg $@
