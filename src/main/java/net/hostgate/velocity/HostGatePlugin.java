package net.hostgate.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyPingEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

@Plugin(
        id = "hostgate",
        name = "Host Gate",
        version = "1.0.5",
        description = "Suppresses Minecraft status pings and silently closes logins for unlisted hostnames"
)
public final class HostGatePlugin {
    private static final String DEFAULT_CONFIG =
            "# Hostnames in velocity.toml [forced-hosts] are allowed by default.\n"
                    + "allowOnlyForcedHosts = true\n"
                    + "\n"
                    + "# Optional allowed hosts.\n"
                    + "additionalAllowedHosts = [\n"
                    + "     # \"*.example.com\"\n"
                    + "]\n";

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Path dataDirectory;

    private volatile Policy policy = Policy.denyAll();

    private volatile Method delegatedConnectionMethod;
    private volatile Method closeConnectionMethod;

    @Inject
    public HostGatePlugin(
            ProxyServer proxyServer,
            Logger logger,
            @DataDirectory Path dataDirectory
    ) {
        this.proxyServer = proxyServer;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        Path tomlFile = dataDirectory.resolve("config.toml");

        try {
            Files.createDirectories(dataDirectory);

            if (Files.notExists(tomlFile)) {
                Files.writeString(
                        tomlFile,
                        DEFAULT_CONFIG,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW
                );
            }

            TomlParseResult config = Toml.parse(tomlFile);

            if (config.hasErrors()) {
                throw new IOException(
                        "Invalid TOML: " + config.errors()
                );
            }

            Object restrictionValue =
                    config.get("allowOnlyForcedHosts");

            if (!(restrictionValue instanceof Boolean restricted)) {
                throw new IOException(
                        "allowOnlyForcedHosts must be a TOML boolean"
                );
            }

            Object hostsValue =
                    config.get("additionalAllowedHosts");

            if (!(hostsValue instanceof TomlArray hosts)) {
                throw new IOException(
                        "additionalAllowedHosts must be a TOML array"
                );
            }

            Set<String> exactHosts = new HashSet<>();
            List<Pattern> wildcardPatterns = new ArrayList<>();

            for (int i = 0; i < hosts.size(); i++) {
                Object value = hosts.get(i);

                if (!(value instanceof String hostPattern)) {
                    throw new IOException(
                            "additionalAllowedHosts entry "
                                    + i
                                    + " must be a string"
                    );
                }

                addHostPattern(
                        hostPattern,
                        exactHosts,
                        wildcardPatterns
                );
            }

            int forcedHostCount = proxyServer
                    .getConfiguration()
                    .getForcedHosts()
                    .size();

            policy = new Policy(
                    true,
                    restricted,
                    Set.copyOf(exactHosts),
                    List.copyOf(wildcardPatterns)
            );

            logger.info(
                    "Host Gate: allowOnlyForcedHosts={}, {} exact extra(s), "
                            + "{} wildcard(s), {} forced host(s)",
                    restricted,
                    exactHosts.size(),
                    wildcardPatterns.size(),
                    forcedHostCount
            );

            if (!restricted) {
                logger.warn(
                        "Host Gate hostname restriction is disabled; "
                                + "IP and other hostnames are allowed"
                );
            } else if (forcedHostCount == 0
                    && exactHosts.isEmpty()
                    && wildcardPatterns.isEmpty()) {
                logger.warn(
                        "No hostnames are allowed; "
                                + "all pings and logins will be denied"
                );
            }
        } catch (IOException | RuntimeException e) {
            policy = Policy.denyAll();

            logger.error(
                    "Could not load valid {}; "
                            + "all pings and logins will be denied",
                    tomlFile,
                    e
            );
        }
    }

    private static void addHostPattern(
            String rawPattern,
            Set<String> exactHosts,
            List<Pattern> wildcardPatterns
    ) throws IOException {
        String value = normalizeHost(rawPattern.strip());

        if (!isValidPattern(value)) {
            throw new IOException(
                    "Invalid additionalAllowedHosts entry: "
                            + rawPattern
            );
        }

        if (value.contains("*")) {
            wildcardPatterns.add(
                    compileWildcard(value)
            );
        } else {
            exactHosts.add(value);
        }
    }

    private static String normalizeHost(String host) {
        return host.toLowerCase(Locale.ROOT);
    }

    private static boolean isValidPattern(String value) {
        if (value.isEmpty()
                || value.length() > 253
                || value.startsWith(".")
                || value.endsWith(".")
                || value.contains("..")) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);

            if (!((character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '-'
                    || character == '.'
                    || character == '*')) {
                return false;
            }
        }

        return true;
    }

    private static Pattern compileWildcard(String wildcard) {
        StringBuilder regex = new StringBuilder("^");
        int literalStart = 0;

        for (int i = 0; i < wildcard.length(); i++) {
            if (wildcard.charAt(i) == '*') {
                regex.append(
                        Pattern.quote(
                                wildcard.substring(
                                        literalStart,
                                        i
                                )
                        )
                );

                regex.append(".*");
                literalStart = i + 1;
            }
        }

        regex.append(
                Pattern.quote(
                        wildcard.substring(literalStart)
                )
        );

        regex.append("$");

        return Pattern.compile(regex.toString());
    }

    private boolean isAllowed(InboundConnection connection) {
        Policy current = policy;

        if (!current.valid()) {
            return false;
        }

        if (!current.allowOnlyForcedHosts()) {
            return true;
        }

        try {
            return connection
                    .getVirtualHost()
                    .map(address ->
                            normalizeHost(
                                    address.getHostString()
                            )
                    )
                    .map(host ->
                            isAllowedHost(host, current)
                    )
                    .orElse(false);
        } catch (RuntimeException e) {
            logger.error(
                    "Could not check hostname; "
                            + "denying connection",
                    e
            );

            return false;
        }
    }

    private boolean isAllowedHost(
            String host,
            Policy current
    ) {
        if (current.exactHosts().contains(host)) {
            return true;
        }

        for (Pattern pattern : current.wildcardPatterns()) {
            if (pattern.matcher(host).matches()) {
                return true;
            }
        }

        return proxyServer
                .getConfiguration()
                .getForcedHosts()
                .keySet()
                .stream()
                .map(HostGatePlugin::normalizeHost)
                .anyMatch(host::equals);
    }

    private boolean closeSilently(
            InboundConnection connection
    ) {
        try {
            Method delegatedMethod =
                    delegatedConnectionMethod;

            if (delegatedMethod == null
                    || !delegatedMethod
                    .getDeclaringClass()
                    .isAssignableFrom(connection.getClass())) {

                delegatedMethod = findDeclaredMethod(
                        connection.getClass(),
                        "delegatedConnection"
                );

                delegatedMethod.setAccessible(true);
                delegatedConnectionMethod = delegatedMethod;
            }

            Object minecraftConnection =
                    delegatedMethod.invoke(connection);

            if (minecraftConnection == null) {
                throw new IllegalStateException(
                        "Velocity delegated connection was null"
                );
            }

            Method closeMethod =
                    closeConnectionMethod;

            if (closeMethod == null
                    || !closeMethod
                    .getDeclaringClass()
                    .isAssignableFrom(
                            minecraftConnection.getClass()
                    )) {

                closeMethod =
                        minecraftConnection
                                .getClass()
                                .getMethod(
                                        "close",
                                        boolean.class
                                );

                closeConnectionMethod = closeMethod;
            }

            closeMethod.invoke(
                    minecraftConnection,
                    true
            );

            return true;
        } catch (ReflectiveOperationException
                 | RuntimeException e) {

            logger.error(
                    "Host Gate could not silently close "
                            + "a rejected connection",
                    e
            );

            return false;
        }
    }

    private static Method findDeclaredMethod(
            Class<?> type,
            String name,
            Class<?>... parameterTypes
    ) throws NoSuchMethodException {
        Class<?> current = type;

        while (current != null) {
            try {
                return current.getDeclaredMethod(
                        name,
                        parameterTypes
                );
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }

        throw new NoSuchMethodException(
                type.getName() + "." + name
        );
    }

    private record Policy(
            boolean valid,
            boolean allowOnlyForcedHosts,
            Set<String> exactHosts,
            List<Pattern> wildcardPatterns
    ) {
        private static Policy denyAll() {
            return new Policy(
                    false,
                    true,
                    Set.of(),
                    List.of()
            );
        }
    }

    @Subscribe
    public void onPing(ProxyPingEvent event) {
        if (!isAllowed(event.getConnection())) {
            event.setResult(
                    ResultedEvent.GenericResult.denied()
            );
        }
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        if (isAllowed(event.getConnection())) {
            return;
        }

        if (closeSilently(event.getConnection())) {
            return;
        }

        /** Failback if for some reason the close connection doesnt work, to prevent allowing anyone to still access invalid hostnames/ips */
        event.setResult(
                PreLoginEvent.PreLoginComponentResult.denied(
                        Component.text("Disconnected")
                )
        );
    }
}
