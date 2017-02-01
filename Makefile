all: otr.svg

clean:
	rm -f otr.svg tests/*.test tests/*.run *.graph TEMP_* partition.svg
	rm -rf __pycache__

RUNS  = $(wildcard tests/run_*.spg)
TESTS = $(filter-out $(RUNS), $(wildcard tests/*.spg))

SPG_ARGS = --latex ../../Papers/ESSoS17/rules.tex

#SPG_ARGS += --verbose
SPG_ARGS += --partition
SPG_ARGS += --merge_const
SPG_ARGS += --merge_branch
SPG_ARGS += --concentrate
SPG_ARGS += --pgraph=partitions.svg
SPG_ARGS += --dump=doc/ruleset.tex

export MALLOC_CHECK_=0

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

tests:: $(sort $(TESTS:.spg=.test))
	@echo "$(words $^) TESTS DONE."

run:: $(sort $(RUNS:.spg=.run))
	@echo "$(words $^) RUNS DONE."

tests/%.svg: tests/%.spg spg.py
	@echo "=== Graph $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@

tests/%.test: tests/%.spg spg.py
	@echo "=== Testing $<"
	-@./spg.py $(filter-out --partition, $(SPG_ARGS)) --input $< --output tests/$*.FAILED.svg --test
	-@mv tests/$*.FAILED.svg $@

tests/%.dot:: tests/%.spg spg.py
	@echo "=== Graph $@"
	./spg.py $(SPG_ARGS) --input $< --output $@

tests/%.run:: tests/%.spg spg.py #FORCE
	@echo "=== Running $@"
	@./spg.py $(SPG_ARGS) --input $< --output $@.svg --run
	@mv $@.svg $@

FORCE:
