.PHONY: test policy-test py-test waivers tf-validate

test: py-test waivers policy-test review-test

py-test:
	python -m pytest -q security/scripts app/logging

waivers:
	python security/scripts/check_waivers.py validate security/waivers/waivers.yaml

policy-test:
	kyverno test policies/kyverno/tests

tf-validate:
	cd terraform && $${TF:-tofu} init -backend=false && $${TF:-tofu} validate

review-test:
	kyverno test policies/kyverno/tests-review
	conftest verify -p policies/conftest/terraform
	! conftest test --parser hcl2 -p policies/conftest/terraform review/terraform/before/main.tf
	conftest test --parser hcl2 -p policies/conftest/terraform review/terraform/after/main.tf
