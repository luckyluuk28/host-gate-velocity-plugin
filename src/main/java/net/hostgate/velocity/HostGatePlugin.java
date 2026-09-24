package net.hostgate.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
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
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Plugin(
        id = "hostgate",
        name = "Host Gate",
        version = "1.1.0",
        description = "Suppresses Minecraft status pings and rejects connections for unlisted hostnames"
)
public final class HostGatePlugin {
    private static final String DEFAULT_CONFIG =
            "allowOnlyForcedHosts = true\n"
                    + "\n"
                    + "additionalAllowedHosts = [\n"
                    + "    # \"mc.example.com\",\n"
                    + "    # \"*.mc.example.com\"\n"
                    + "]\n"
                    + "\n"
                    + "rejectMode = \"silent\"\n"
                    + "disconnectMessage = \"Disconnected\"\n"
                    + "\n"
                    + "logRejectedConnections = false\n"
                    + "logRejectedPings = false\n"
                    + "\n"
                    + "failClosed = true\n";

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
        try {
            Files.createDirectories(dataDirectory);

            Path tomlFile = getConfigPath();

            if (Files.notExists(tomlFile)) {
                Files.writeString(
                        tomlFile,
                        DEFAULT_CONFIG,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW
                );
            }
        } catch (IOException e) {
            policy = Policy.denyAll();
            logger.error("Could not create Host Gate configuration", e);
        }

        reloadConfiguration();

        CommandMeta meta = proxyServer
                .getCommandManager()
                .metaBuilder("hostgate")
                .plugin(this)
                .build();

        proxyServer
                .getCommandManager()
                .register(meta, new HostGateCommand());
    }

    private boolean reloadConfiguration() {
        Path tomlFile = getConfigPath();
        boolean failClosed = true;

        try {
            TomlParseResult config = Toml.parse(tomlFile);

            if (config.hasErrors()) {
                throw new IOException(
                        "Invalid TOML: " + config.errors()
                );
            }

            failClosed = getBoolean(
                    config,
                    "failClosed",
                    true
            );

            boolean allowOnlyForcedHosts = getBoolean(
                    config,
                    "allowOnlyForcedHosts",
                    true
            );

            String rejectModeValue = getString(
                    config,
                    "rejectMode",
                    "silent"
            );

            RejectMode rejectMode;

            try {
                rejectMode = RejectMode.valueOf(
                        rejectModeValue
                                .strip()
                                .toUpperCase(Locale.ROOT)
                );
            } catch (IllegalArgumentException e) {
                throw new IOException(
                        "rejectMode must be \"silent\" or \"disconnect\""
                );
            }

            String disconnectMessage = getString(
                    config,
                    "disconnectMessage",
                    "Disconnected"
            );

            boolean logRejectedConnections = getBoolean(
                    config,
                    "logRejectedConnections",
                    false
            );

            boolean logRejectedPings = getBoolean(
                    config,
                    "logRejectedPings",
                    false
            );

            Set<String> exactHosts = new HashSet<>();
            List<Pattern> wildcardPatterns = new ArrayList<>();

            Object hostsValue = config.get("additionalAllowedHosts");

            if (hostsValue != null) {
                if (!(hostsValue instanceof TomlArray hosts)) {
                    throw new IOException(
                            "additionalAllowedHosts must be a TOML array"
                    );
                }

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
            }

            int forcedHostCount = proxyServer
                    .getConfiguration()
                    .getForcedHosts()
                    .size();

            policy = new Policy(
                    true,
                    allowOnlyForcedHosts,
                    Set.copyOf(exactHosts),
                    List.copyOf(wildcardPatterns),
                    rejectMode,
                    disconnectMessage,
                    logRejectedConnections,
                    logRejectedPings
            );

            logger.info(
                    "Host Gate loaded: allowOnlyForcedHosts={}, rejectMode={}, "
                            + "{} exact extra(s), {} wildcard(s), {} forced host(s)",
                    allowOnlyForcedHosts,
                    rejectMode.name().toLowerCase(Locale.ROOT),
                    exactHosts.size(),
                    wildcardPatterns.size(),
                    forcedHostCount
            );

            if (!allowOnlyForcedHosts) {
                logger.warn(
                        "Host Gate hostname restriction is disabled; "
                                + "IP and other hostnames are allowed"
                );
            } else if (forcedHostCount == 0
                    && exactHosts.isEmpty()
                    && wildcardPatterns.isEmpty()) {
                logger.warn(
                        "No hostnames are allowed; "
                                + "all pings and logins will be rejected"
                );
            }

            return true;
        } catch (IOException | RuntimeException e) {
            policy = failClosed
                    ? Policy.denyAll()
                    : Policy.allowAll();

            logger.error(
                    "Could not load valid {}; Host Gate is failing {}",
                    tomlFile,
                    failClosed ? "closed" : "open",
                    e
            );

            return false;
        }
    }

    private Path getConfigPath() {
        return dataDirectory.resolve("config.toml");
    }

    private static boolean getBoolean(
            TomlParseResult config,
            String key,
            boolean defaultValue
    ) throws IOException {
        Object value = config.get(key);

        if (value == null) {
            return defaultValue;
        }

        if (!(value instanceof Boolean booleanValue)) {
            throw new IOException(
                    key + " must be a TOML boolean"
            );
        }

        return booleanValue;
    }

    private static String getString(
            TomlParseResult config,
            String key,
            String defaultValue
    ) throws IOException {
        Object value = config.get(key);

        if (value == null) {
            return defaultValue;
        }

        if (!(value instanceof String stringValue)) {
            throw new IOException(
                    key + " must be a TOML string"
            );
        }

        return stringValue;
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
                    .map(InetSocketAddress::getHostString)
                    .map(HostGatePlugin::normalizeHost)
                    .map(host -> isAllowedHost(host, current))
                    .orElse(false);
        } catch (RuntimeException e) {
            logger.error(
                    "Could not check hostname; denying connection",
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

    private String getConnectionHost(
            InboundConnection connection
    ) {
        try {
            return connection
                    .getVirtualHost()
                    .map(InetSocketAddress::getHostString)
                    .orElse("<unknown>")
                    .replaceAll("\\p{Cntrl}", "?");
        } catch (RuntimeException e) {
            return "<unknown>";
        }
    }

    private void logRejected(
            String type,
            InboundConnection connection
    ) {
        logger.info(
                "Host Gate rejected {} from {} using host '{}'",
                type,
                connection.getRemoteAddress(),
                getConnectionHost(connection)
        );
    }

    private boolean closeSilently(
            InboundConnection connection
    ) {
        try {
            Method delegatedMethod = delegatedConnectionMethod;

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

            Method closeMethod = closeConnectionMethod;

            if (closeMethod == null
                    || !closeMethod
                    .getDeclaringClass()
                    .isAssignableFrom(
                            minecraftConnection.getClass()
                    )) {

                closeMethod = minecraftConnection
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
                    "Host Gate could not silently close rejected connection",
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

    @Subscribe
    public void onPing(ProxyPingEvent event) {
        if (isAllowed(event.getConnection())) {
            return;
        }

        Policy current = policy;

        if (current.logRejectedPings()) {
            logRejected(
                    "ping",
                    event.getConnection()
            );
        }

        event.setResult(
                ResultedEvent.GenericResult.denied()
        );
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        if (isAllowed(event.getConnection())) {
            return;
        }

        Policy current = policy;

        if (current.logRejectedConnections()) {
            logRejected(
                    "login",
                    event.getConnection()
            );
        }

        if (current.rejectMode() == RejectMode.DISCONNECT) {
            event.setResult(
                    PreLoginEvent.PreLoginComponentResult.denied(
                            Component.text(
                                    current.disconnectMessage()
                            )
                    )
            );

            return;
        }

        if (closeSilently(event.getConnection())) {
            return;
        }

        event.setResult(
                PreLoginEvent.PreLoginComponentResult.denied(
                        Component.text(
                                current.disconnectMessage()
                        )
                )
        );
    }

    private final class HostGateCommand
            implements SimpleCommand {

        @Override
        public void execute(Invocation invocation) {
            if (!invocation
                    .source()
                    .hasPermission("hostgate.reload")) {

                invocation
                        .source()
                        .sendMessage(
                                Component.text(
                                        "You do not have permission to use this command."
                                )
                        );

                return;
            }

            String[] arguments = invocation.arguments();

            if (arguments.length != 1
                    || !arguments[0].equalsIgnoreCase("reload")) {

                invocation
                        .source()
                        .sendMessage(
                                Component.text(
                                        "Usage: /hostgate reload"
                                )
                        );

                return;
            }

            if (reloadConfiguration()) {
                invocation
                        .source()
                        .sendMessage(
                                Component.text(
                                        "Host Gate configuration reloaded."
                                )
                        );
            } else {
                invocation
                        .source()
                        .sendMessage(
                                Component.text(
                                        "Host Gate configuration could not be loaded. Check the proxy log."
                                )
                        );
            }
        }

        @Override
        public List<String> suggest(
                Invocation invocation
        ) {
            if (!invocation
                    .source()
                    .hasPermission("hostgate.reload")) {
                return List.of();
            }

            String[] arguments = invocation.arguments();

            if (arguments.length == 0) {
                return List.of("reload");
            }

            if (arguments.length == 1
                    && "reload"
                    .startsWith(
                            arguments[0]
                                    .toLowerCase(Locale.ROOT)
                    )) {
                return List.of("reload");
            }

            return List.of();
        }
    }

    private enum RejectMode {
        SILENT,
        DISCONNECT
    }

    private record Policy(
            boolean valid,
            boolean allowOnlyForcedHosts,
            Set<String> exactHosts,
            List<Pattern> wildcardPatterns,
            RejectMode rejectMode,
            String disconnectMessage,
            boolean logRejectedConnections,
            boolean logRejectedPings
    ) {
        private static Policy denyAll() {
            return new Policy(
                    false,
                    true,
                    Set.of(),
                    List.of(),
                    RejectMode.SILENT,
                    "Disconnected",
                    false,
                    false
            );
        }

        private static Policy allowAll() {
            return new Policy(
                    true,
                    false,
                    Set.of(),
                    List.of(),
                    RejectMode.SILENT,
                    "Disconnected",
                    false,
                    false
            );
        }
    }
}
