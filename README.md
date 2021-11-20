# Standalone APIcast

This is a PoC on how to implement a detached APIcast without a backend to do simple authentication.

## Simple Authentication

Currently there are 2 types available:

- **none** - there is no authentication at all. All request are forwarded.
- **key** - Authorized keys are stored in a file and the policy checks the request credentials against those keys.

### Configuration

The detached APIcast uses a `config.json` file to configure its behavior. You will need to add the policy the  `policy_chain` and configure the type of authentication using the `auth_type` field. If using the **keys** option, by default the file needs to be available on `/opt/app/keys`.

You can check the [conf/config.json](conf/config.json) for an example.

### Local Environment

If you want to give it a try, there is a `docker-compose.yaml` file with a working setup. 