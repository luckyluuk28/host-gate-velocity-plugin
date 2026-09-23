# Host Gate

A Velocity plugin that limits Minecraft status pings and logins by the hostname
sent in the client's handshake.

By default, Host Gate allows hostnames declared in Velocity's `[forced-hosts]`
section. You can allow additional exact names or wildcard patterns.

## Requirements

- Java 17 or newer
- Maven 3
- A compatible Velocity proxy

## Build

```sh
mvn clean package
```

Upload `target/host-gate-1.0.4.jar` to Velocity's `plugins/` directory. Remove
older Host Gate JARs from that directory, then restart Velocity.

## Configuration

On first start, the plugin creates `plugins/hostgate/config.toml`:

```toml
allowOnlyForcedHosts = true

additionalAllowedHosts = [
]
```

For example:

```toml
allowOnlyForcedHosts = true

additionalAllowedHosts = [
  "server.example.com",
  "*.example.com",
]
```

Restart Velocity after changing this file.

- `allowOnlyForcedHosts = true` allows the keys in Velocity's `[forced-hosts]`
  section plus `additionalAllowedHosts`.
- `allowOnlyForcedHosts = false` allows any hostname, including direct IP
  connections. The additional list has no effect in this mode.
- `*` matches any sequence of characters, including dots. For example,
  `*.example.com` matches `play.example.com`, but
  not `example.com`.
- Patterns are matched against the whole hostname. Matching ignores case.
- Invalid configuration denies all pings and logins.

Adding a hostname to `additionalAllowedHosts` only permits the connection. It
does not create a Velocity forced-host route; Velocity's usual `try` servers
apply unless the hostname also has a forced-host entry.

## What clients see

A disallowed server-list ping receives no Minecraft status response. A
disallowed login receives a generic disconnect message.

Host Gate checks the hostname claimed by the Minecraft client. A modified
client can claim an allowed hostname while connecting directly to the IP, and
a TCP scan can still find the listener. Keep backend servers private and
configure Velocity forwarding securely.