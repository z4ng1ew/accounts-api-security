.PHONY: test policy-test py-test waivers tf-validate

test: py-test waivers policy-test

py-test:
	python -m pytest -q security/scripts app/logging

waivers:
	python security/scripts/check_waivers.py validate security/waivers/waivers.yaml

policy-test:
	kyverno test policies/kyverno/tests

tf-validate:
	cd terraform && terraform init -backend=false && terraform validate
