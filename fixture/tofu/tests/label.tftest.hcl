# What tofu-ci.yml's `test` job runs against the fixture. The module has no
# provider, so `tofu test` plans offline; a real caller's tests would use
# mock_provider blocks for the same reason.

run "label_joins_the_name_and_the_count" {
  command = plan

  variables {
    name     = "web"
    replicas = 3
  }

  assert {
    condition     = output.label == "web-3"
    error_message = "label should be the name and the count joined with a hyphen."
  }
}

run "zero_replicas_is_refused" {
  command = plan

  variables {
    replicas = 0
  }

  expect_failures = [var.replicas]
}
