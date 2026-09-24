# Host Gate

A Velocity plugin that limits Minecraft status pings and logins based on the
hostname sent in the client's handshake.

By default, Host Gate allows hostnames configured in Velocity's
`[forced-hosts]` section. Additional hostnames and IP addresses can be allowed
through its configuration.

Rejected status pings receive no Minecraft status response. Rejected logins are
silently closed by default.

## Requirements

* Java 25
* Velocity 4.x

## Build

```sh
mvn clean package
```

The built plugin is available in `target/`.

Copy the JAR to Velocity's `plugins/` directory, remove any older Host Gate
JARs, and restart the proxy.

## Configuration

Host Gate creates its configuration automatically on first start:

```text
plugins/hostgate/config.toml
```

The generated configuration documents all available options.

Allowed entries can include exact hostnames, exact IPv4/IPv6 addresses, and
single-level DNS wildcards such as `*.example.com`.

## Security considerations

Host Gate checks the hostname claimed by the Minecraft client. It makes generic
IP-based Minecraft scanning less useful, but it is not an authentication
mechanism.
