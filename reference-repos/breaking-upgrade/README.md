# Breaking upgrade demo

This deliberately vulnerable Node repository has a test that documents a legacy Axios 0.x compatibility requirement. SAVEMit can plan the secure Axios upgrade, but the isolated validation test must fail once Axios 1.x is installed.

Expected outcome: no change is applied to the original repository and no pull request should be opened automatically. A human must migrate the application away from its 0.x-only behavior, then run SAVEMit again.
