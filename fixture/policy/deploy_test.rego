package fixture.deploy_test

import rego.v1

import data.fixture.deploy

test_a_change_to_the_module_on_main_deploys if {
	deploy.deploy with input as {"branch": "main", "tag": "", "changed_files": ["fixture/tofu/main.tf"]}
}

test_a_change_elsewhere_does_not_deploy if {
	not deploy.deploy with input as {"branch": "main", "tag": "", "changed_files": ["README.md"]}
}

test_another_branch_does_not_deploy if {
	not deploy.deploy with input as {"branch": "feature", "tag": "", "changed_files": ["fixture/tofu/main.tf"]}
}

test_a_tag_does_not_deploy if {
	not deploy.deploy with input as {"branch": "main", "tag": "v1.0.0", "changed_files": ["fixture/tofu/main.tf"]}
}
