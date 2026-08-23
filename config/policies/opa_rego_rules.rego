package netra.authz

default allow = false

# Allow execution only if warrant is active and not expired
allow {
    input.warrant.status == "ACTIVE"
    time.now_ns() < time.parse_rfc3339_ns(input.warrant.expires_at)
    input.operator.clearance_level >= input.case.required_clearance
}

# Deny if scope exceeds authorized boundaries
deny[msg] {
    input.requested_module == "MODULE_A"
    not input.warrant.scope.android_logical_acquisition
    msg := "Android logical acquisition not authorized by warrant."
}
