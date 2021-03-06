#
# File formats:
#
# spg  - SPG input
# spga - Analyzed SPG file
# spgc - Assertion-checked SPG file
# spgr - SPG run log
# spgp - Partitioned SPG file
#

all: tests/complex_OTRrev3.spgc

clean:
	rm -f otr.* tests/*.spg? tests/*.pdf tests/unittests.log *.graph TEMP_* partitions.svg
	rm -rf __pycache__

EXCLUDE = tests/complex_OTRrev3.spg
RUNS    = $(wildcard tests/run_*.spg)
TESTS   = $(filter-out $(RUNS) $(EXCLUDE), $(wildcard tests/*.spg))

#SPG_ARGS = --latex ../../Papers/ESSoS17/rules.tex

#SPG_ARGS += --verbose
#SPG_ARGS += --partition
#SPG_ARGS += --merge_const
#SPG_ARGS += --merge_branch
#SPG_ARGS += --concentrate
#SPG_ARGS += --pgraph=partitions.svg
#SPG_ARGS += --dump=doc/ruleset.tex

ifneq ($(FORCE),)
FORCE_TESTS=FORCE
F=-
endif

V ?= @

export MALLOC_CHECK_=0

test:: $(sort $(TESTS:.spg=.spgc)) $(sort $(RUNS:.spg=.spgr)) tests/unittests.log 
	@echo "$(words $^) TESTS DONE."

run:: $(sort $(RUNS:.spg=.spgr))
	@echo "$(words $^) MODELS EXECUTED."

tests/unittests.log:
	@PYTHONPATH=. ./tests/unittests.py
	@touch $@

tests/%.spga: tests/%.spg spg_analyze
	@echo "=== Analyzing $<"
	$(V)$(F)./spg_analyze $(SPG_ARGS) --input $< --output $@

tests/%.spgc: tests/%.spga spg_assert
	@echo "=== Checking $<"
	$(V)$(F)./spg_assert --input $< --output $@

tests/%.spgr: tests/%.spgc spg_run $(FORCE_TESTS)
	@echo "=== Running $<"
	$(V)$(F)./spg_run $(SPG_ARGS) --input $< --output $@

tests/%.spgp: tests/%.spgc spg_partition
	@echo "=== Partitioning $<"
	$(V)$(F)./spg_partition $(SPG_ARGS) --input $< --output $@

tests/%.pdf: tests/% spg_pdf
	@echo "=== PDF from SPGx $@"
	$(V)./spg_pdf $(SPG_ARGS) --input $< --output $@

FORCE:
