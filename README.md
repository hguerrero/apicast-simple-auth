# Standalone APIcast

This is a PoC on how to implement a detached APIcast without a backend to do simple authentication.

## Simple Authentication

Currently there are 2 types available:

- **none** - there is no authentication at all. All request are forwarded.
- **key** - Authorized keys are stored in a file or the configuration. The policy checks the request credentials against those keys.

### Configuration

The detached APIcast's behavior is configured via a `config.json` file. You must add the policy to the `policy chain` and set the authentication type using the `auth type` field. With the `keys file` option, you can indicate the location of a file containing your authorized keys; by default, the file path is `/opt/app/keys`. In the `keys` element of the policy configuration, you can also provide a list of keys. If both options exist, the policy will merge both lists and validate the credentials against the aggregate.

You can check the [conf/config.json](conf/config.json) for an example.

### Local Environment

If you want to give it a try, there is a `docker-compose.yaml` file with a working setup. 