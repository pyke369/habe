#!/bin/sh

PROGNAME=habe
KEY ?= XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

# build targets
$(PROGNAME): *.go
	@-go build -trimpath -o $(PROGNAME) *.go
	@-strip $(PROGNAME) 2>/dev/null || true
	@-upx -9 $(PROGNAME) 2>/dev/null || true
distclean:
	@rm -f $(PROGNAME)

# run targets
run: $(PROGNAME)
	@./$(PROGNAME) $(KEY) Automatic_backup_*.tar
