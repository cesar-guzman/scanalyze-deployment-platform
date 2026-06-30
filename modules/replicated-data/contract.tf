# replicated-data is a sub-module called by data-foundation.
# It does NOT produce its own contract.
# It does NOT have an independent lifecycle or state.
#
# replicated-data is a future HA/DR implementation surface.
# It is not an active single-region lifecycle in M1.
# It must not create resources, contracts, or independent state in M1.
# Before Enterprise HA or actual replication resources are implemented,
# the architecture must re-evaluate whether replicated-data requires
# a separate lifecycle/state boundary.
