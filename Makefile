# Runs the tests in a pinned Zeek container (no local Zeek needed).
ZEEK_IMAGE ?= zeek/zeek:9.0.0
ZEEK_RUN = docker run --rm -u "$$(id -u):$$(id -g)" -e HOME=/tmp \
	-v "$(CURDIR)":/src -w /src/testing $(ZEEK_IMAGE)

.PHONY: test test-update traces

test:
	$(ZEEK_RUN) btest -c btest.cfg -d

# Accepts the current outputs as new baselines: review the diff first.
test-update:
	$(ZEEK_RUN) btest -c btest.cfg -U

traces:
	python3 testing/Scripts/gen-traces.py
