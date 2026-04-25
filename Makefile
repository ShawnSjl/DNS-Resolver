# Go related config
GO      := go
CMD_DIR := cmd

# Find all program under cmd
CMDS := $(notdir $(wildcard $(CMD_DIR)/*))

.PHONY: all build clean $(CMDS)

all: build

build: $(CMDS)

# Build for all cmd/<name>
$(CMDS):
	@echo "==> building $@"
	$(GO) build -o $@ ./$(CMD_DIR)/$@

clean:
	rm -f $(CMDS)