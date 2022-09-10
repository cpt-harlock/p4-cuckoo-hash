P4C = p4c-bm2-ss
P4ARGS = --p4v 16
all: main.p4
	$(P4C) $(P4ARGS) $^
	
