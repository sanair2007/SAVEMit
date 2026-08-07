# Unreachable dependency demo

`lodash` is present in the dependency manifest but no source file imports it. SAVEMit records this as no static reachability evidence and lowers the policy priority for its findings.
