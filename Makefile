TXVIZ ?= txviz

# XXX: Must keep STYLESHEETS in sync with STYLE_FLAGS manually
STYLESHEETS=docs/diagrams/style.css
STYLE_FLAGS=\
 --css docs/diagrams/style.css\
 --background-color \\\#FFFFFF

DIAGRAM_SOURCES=\
	docs/diagrams/overview.json \
	docs/diagrams/deposit.json \
	docs/diagrams/withdrawal.json \

DIAGRAMS=$(DIAGRAM_SOURCES:.json=.svg)

%.svg: %.json $(STYLESHEETS)
	$(TXVIZ) $(STYLE_FLAGS) $< -o $@

diagrams: $(DIAGRAMS)
all: diagrams

.phony: all diagrams
