all: otr.svg

otr.svg: models/OTRrev3.spg
	./spg.py --input $< --output $@
