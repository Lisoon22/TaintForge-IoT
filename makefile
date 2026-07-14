PYTHON ?= python
DEMO_ARGS ?=
ANALYZE_OUT ?= workdir/static_analysis
ANALYZE_NETWORK ?= auto
ANALYZE_ARGS ?=

.PHONY: doctor test demo-static analyze-static clean

doctor:
	@missing=0; \
	for tool in $(PYTHON) gcc as ld pkg-config readelf sudo strace timeout chroot mount unshare ip iptables ss conntrack jq; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			echo "[ok] $$tool"; \
		else \
			echo "[missing] $$tool"; \
			missing=1; \
		fi; \
	done; \
	if command -v qemu-i386 >/dev/null 2>&1 || command -v qemu-i386-static >/dev/null 2>&1; then \
		echo "[ok] qemu-i386"; \
	else \
		echo "[missing] qemu-i386 or qemu-i386-static"; \
		missing=1; \
	fi; \
	if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists glib-2.0 capstone; then \
		echo "[ok] glib-2.0 and capstone development metadata"; \
	else \
		echo "[missing] pkg-config metadata for glib-2.0 and capstone"; \
		missing=1; \
	fi; \
	if test -f /usr/include/qemu-plugin.h || test -f "$$HOME/qemu/include/qemu/qemu-plugin.h" || test -f "$$HOME/qemu/include/qemu-plugin.h"; then \
		echo "[ok] QEMU plugin header"; \
	else \
		echo "[missing] qemu-plugin.h (system header or configured QEMU tree)"; \
		missing=1; \
	fi; \
	exit $$missing

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

demo-static:
	PYTHONPATH=. $(PYTHON) scripts/run_phase2_static_demo.py --force $(DEMO_ARGS)

analyze-static:
	@if test -z "$(strip $(SAMPLE))"; then \
		echo "usage: make analyze-static SAMPLE=/path/to/static-i386-elf" >&2; \
		exit 2; \
	fi
	PYTHONPATH=. $(PYTHON) scripts/run_static_pipeline.py "$(SAMPLE)" \
		--out "$(ANALYZE_OUT)" \
		--network "$(ANALYZE_NETWORK)" \
		--force $(ANALYZE_ARGS)

clean:
	rm -rf build workdir samples/phase2_demo_i386 samples/c2_record_client_x86_64
	find scripts taintforge_env tests -type d -name __pycache__ -prune -exec rm -rf {} +
	find scripts taintforge_env tests -type f -name '*.pyc' -delete
