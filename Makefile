all: otr.svg

clean:
	rm -f otr.* tests/*.test tests/*.run *.graph TEMP_* partitions.svg
	rm -rf __pycache__

RUNS  = $(wildcard tests/run_*.spg)
TESTS = $(filter-out $(RUNS), $(wildcard tests/*.spg))

SPG_ARGS = --latex ../../Papers/ESSoS17/rules.tex

SPG_ARGS += --verbose
SPG_ARGS += --partition
SPG_ARGS += --merge_const
SPG_ARGS += --merge_branch
#SPG_ARGS += --concentrate
#SPG_ARGS += --pgraph=partitions.svg
SPG_ARGS += --dump=doc/ruleset.tex

ifneq ($(FORCE),)
FORCE_TESTS=FORCE
F=-
endif

V ?= @

export MALLOC_CHECK_=0

otr.svg: models/OTRrev3.spg spg_analyze
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output TEMP_$@
	$(V)mv TEMP_$@ $@

otr.json: models/OTRrev3.spg spg_analyze
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output TEMP_$@
	$(V)mv TEMP_$@ $@

otr.dot: models/OTRrev3.spg spg_analyze
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output TEMP_$@
	$(V)mv TEMP_$@ $@

otr.run: models/OTRrev3.spg spg_analyze
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output TEMP_$@ --run
	$(V)mv TEMP_$@ $@

otr.graph: models/OTRrev3.spg spg_analyze
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output TEMP_$@
	$(V)mv TEMP_$@ $@

test:: $(sort $(TESTS:.spg=.test)) $(sort $(RUNS:.spg=.run))
	@echo "$(words $^) TESTS DONE."

tests/%.svg: tests/%.spg spg_analyze
	@echo "=== Graph $@"
	$(V)./spg_analyze $(SPG_ARGS) --input $< --output $@

tests/%.test: tests/%.spg spg_analyze
	@echo "=== Testing $<"
	$(V)./spg_analyze $(filter-out --partition --verbose, $(SPG_ARGS)) --input $< --output tests/$*.FAILED.svg --test
	-@mv tests/$*.FAILED.svg $@

TEST_ARGS = $(filter-out --partition --verbose, $(SPG_ARGS))

tests/%.dot:: tests/%.spg spg_analyze
	@echo "=== Graph $@"
	$(V)./spg_analyze $(TEST_ARGS) --input $< --output $@

tests/%.run:: tests/%.spg spg_analyze $(FORCE_TESTS)
	@echo "=== Running $@"
	$(V)$(F)./spg_analyze $(TEST_ARGS) --input $< --output $@.svg --run
	$(V)$(F)mv $@.svg $@

FORCE:
