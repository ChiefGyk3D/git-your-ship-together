# The fixture's one policy: what tofu-ci.yml's `policy` job holds to
# `opa fmt`, `opa check --strict` and `opa test`. The shape is a deploy
# decision of the kind a Spacelift push policy makes: deploy from the default
# branch, never from a tag, and only when a file the deployment reads changed.

package fixture.deploy

import rego.v1

deploy if {
	input.branch == "main"
	input.tag == ""
	some path in input.changed_files
	startswith(path, "fixture/tofu/")
}
