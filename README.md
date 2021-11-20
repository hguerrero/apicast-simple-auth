# Standalone APIcast with Simple Authentication

This is a PoC on how to implement a detached APIcast without a backend to do simple authentication.

Currently there are 2 types available:

- **none** - there is no authentication at all. All request are forwarded.
- **key** - Authorized keys are stored in a file and the policy checks the request credentials against those keys.

You need to add the policy to your `policy_chain` and configure the type of authentication using the `auth_type` field. You can check the [conf/config.json](conf/config.json) for an example.