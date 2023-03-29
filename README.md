# Standalone APIcast

This is a proof-of-concept for implementing a detached APIcast without a backend to perform simple authentication.

## Supported authentication patterns

This policy supports the following 3scale authentication patterns out of the box:

- **Standard API Keys:** Single randomized strings or hashes acting as an identifier and a secret token

## Simple Authentication Policy

There are now two types available:

- **none** - There is no authentication at all. All requests are routed.
- **key** - The configuration or a dedicated file stores authorized keys. The policy compares the request credentials to those keys.

**API key**

By default, the name of the key parameter is `user_key`. You can change the value in your service configuration.

### Configuration

A `config.json` file is used to configure the behavior of the detached APIcast. The policy must be added to the `policy chain`, and the authentication type must be specified in the `auth type` field. You can specify the location of a file containing your authorized keys using the `keys file` option; the default file path is `/opt/app/keys`. You can also give a list of keys in the policy configuration's `keys` field. If both alternatives are available, the policy will combine them and authenticate the credentials against the aggregate.

You can check the [conf/config.json](conf/config.json) for an example.

### Local Environment

There is a [docker-compose.yaml](docker-compose.yaml) file with a working configuration if you want to give it a try.