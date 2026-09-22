# tflint with its built-in rules only; no plugin, so `tflint --init` fetches nothing.
config {
  call_module_type = "local"
}

rule "terraform_required_version" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}
