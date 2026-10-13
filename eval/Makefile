# Reproducible evaluation (see README). DATA holds the downloaded captures.
DATA ?= data
OUT ?= out
PY_IMAGE = hostprofile-eval

.PHONY: eval check features results compare

eval: check features results

check:
	cd $(DATA) && sha256sum -c $(CURDIR)/data.sha256

features:
	./features.sh $(DATA) $(OUT)

results:
	docker build -q -t $(PY_IMAGE) . >/dev/null
	docker run --rm -u "$$(id -u):$$(id -g)" -v "$$(realpath $(DATA))":/data:ro \
		-v "$$(realpath $(OUT))":/out -v "$(CURDIR)":/eval:ro $(PY_IMAGE) \
		python /eval/evaluate.py /data /out

# Detector comparison on the development days (chooses the holdout detector).
compare:
	docker build -q -t $(PY_IMAGE) . >/dev/null
	docker run --rm -u "$$(id -u):$$(id -g)" -v "$$(realpath $(DATA))":/data:ro \
		-v "$$(realpath $(OUT))":/out -v "$(CURDIR)":/eval:ro -w /eval $(PY_IMAGE) \
		python /eval/compare.py /data /out
