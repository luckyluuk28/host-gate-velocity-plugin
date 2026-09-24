package net.hostgate.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyPingEvent;
import com.velocitypowered.api.event.proxy.ProxyReloadEvent;
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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

@Plugin(
        id = "hostgate",
        name = "Host Gate",
        version = "1.1.0",
        description = "Suppresses Minecraft status pings and rejects connections for unlisted hostnames"
)
public final class HostGatePlugin {
    private static final long CONFIG_VERSION = 1;
    private static final String RELOAD_PERMISSION = "hostgate.reload";

    private static final String DEFAULT_CONFIG =
            "configVersion = 1\n"
                    + "\n"
                    + "# Restrict connections to Velocity forced-hosts plus additionalAllowedHosts.\n"
                    + "allowOnlyForcedHosts = true\n"
                    + "\n"
                    + "# Extra allowed hostnames or IP addresses.\n"
                    + "# DNS wildcards match exactly one label.\n"
                    + "additionalAllowedHosts = [\n"
                    + "    # \"mc.example.com\",\n"
                    + "    # \"*.example.com\",\n"
                    + "    # \"203.0.113.10\",\n"
                    + "    # \"2001:db8::10\"\n"
                    + "]\n"
                    + "\n"
                    + "# \"silent\" closes rejected logins without a Minecraft disconnect packet.\n"
                    + "# \"disconnect\" sends disconnectMessage instead.\n"
                    + "rejectMode = \"silent\"\n"
                    + "disconnectMessage = \"Disconnected\"\n"
                    + "\n"
                    + "# Log rejected login attempts and status pings.\n"
                    + "logRejectedConnections = false\n"
                    + "logRejectedPings = false\n"
                    + "\n"
                    + "# Deny all connections if the configuration cannot be loaded.\n"
                    + "failClosed = true\n";

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Path dataDirectory;

    private final AtomicBoolean silentCloseUnavailable =
            new AtomicBoolean(false);

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

            reloadConfiguration();
        } catch (IOException e) {
            policy = Policy.denyAll();

            logger.error(
                    "Could not initialize Host Gate configuration; "
                            + "all connections will be rejected",
                    e
            );
        }

        CommandMeta meta = proxyServer
                .getCommandManager()
                .metaBuilder("hostgate")
                .plugin(this)
                .build();

        proxyServer
                .getCommandManager()
                .register(meta, new HostGateCommand());
    }

    @Subscribe
    public void onProxyReload(ProxyReloadEvent event) {
        silentCloseUnavailable.set(false);
        reloadConfiguration();
    }

    private Path getConfigPath() {
        return dataDirectory.resolve("config.toml");
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

            validateConfigVersion(config);

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

            RejectMode rejectMode = parseRejectMode(
                    getString(
                            config,
                            "rejectMode",
                            "silent"
                    )
            );

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

            Object hostsValue =
                    config.get("additionalAllowedHosts");

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
                    "Host Gate loaded: allowOnlyForcedHosts={}, "
                            + "rejectMode={}, {} exact extra(s), "
                            + "{} wildcard(s), {} forced host(s)",
                    allowOnlyForcedHosts,
                    rejectMode.name()
                            .toLowerCase(Locale.ROOT),
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

    private static void validateConfigVersion(
            TomlParseResult config
    ) throws IOException {
        Object value = config.get("configVersion");

        if (value == null) {
            return;
        }

        if (!(value instanceof Long version)) {
            throw new IOException(
                    "configVersion must be a TOML integer"
            );
        }

        if (version != CONFIG_VERSION) {
            throw new IOException(
                    "Unsupported configVersion: "
                            + version
                            + " (expected "
                            + CONFIG_VERSION
                            + ")"
            );
        }
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

    private static RejectMode parseRejectMode(
            String value
    ) throws IOException {
        try {
            return RejectMode.valueOf(
                    value.strip()
                            .toUpperCase(Locale.ROOT)
            );
        } catch (IllegalArgumentException e) {
            throw new IOException(
                    "rejectMode must be \"silent\" or \"disconnect\""
            );
        }
    }

    private static void addHostPattern(
            String rawPattern,
            Set<String> exactHosts,
            List<Pattern> wildcardPatterns
    ) throws IOException {
        String value = normalizeHost(rawPattern);

        if (value.isEmpty()) {
            throw new IOException(
                    "additionalAllowedHosts entries cannot be empty"
            );
        }

        if (value.contains(":")) {
            if (value.contains("*")) {
                throw new IOException(
                        "IP addresses cannot contain wildcards: "
                                + rawPattern
                );
            }

            String canonical = canonicalizeIpv6(value);

            if (canonical == null) {
                throw new IOException(
                        "Invalid IPv6 address: "
                                + rawPattern
                );
            }

            exactHosts.add(canonical);
            return;
        }

        if (looksLikeIpv4Pattern(value)) {
            if (value.contains("*")) {
                throw new IOException(
                        "IP addresses cannot contain wildcards: "
                                + rawPattern
                );
            }

            String canonical = canonicalizeIpv4(value);

            if (canonical == null) {
                throw new IOException(
                        "Invalid IPv4 address: "
                                + rawPattern
                );
            }

            exactHosts.add(canonical);
            return;
        }

        if (!isValidHostnamePattern(value)) {
            throw new IOException(
                    "Invalid additionalAllowedHosts entry: "
                            + rawPattern
            );
        }

        if (value.contains("*")) {
            wildcardPatterns.add(
                    compileHostnameWildcard(value)
            );
        } else {
            exactHosts.add(value);
        }
    }

    private static String normalizeHost(String host) {
        String value = host
                .strip()
                .toLowerCase(Locale.ROOT);

        if (value.startsWith("[")
                && value.endsWith("]")
                && value.length() > 2) {

            value = value.substring(
                    1,
                    value.length() - 1
            );
        }

        if (!value.contains(":")
                && value.endsWith(".")) {

            value = value.substring(
                    0,
                    value.length() - 1
            );
        }

        String ipv4 = canonicalizeIpv4(value);

        if (ipv4 != null) {
            return ipv4;
        }

        String ipv6 = canonicalizeIpv6(value);

        if (ipv6 != null) {
            return ipv6;
        }

        return value;
    }

    private static String canonicalizeIpv4(
            String value
    ) {
        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return null;
        }

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];

            if (part.isEmpty()
                    || part.length() > 3) {
                return null;
            }

            for (int j = 0; j < part.length(); j++) {
                if (!Character.isDigit(
                        part.charAt(j)
                )) {
                    return null;
                }
            }

            int octet;

            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return null;
            }

            if (octet > 255) {
                return null;
            }

            if (i > 0) {
                result.append('.');
            }

            result.append(octet);
        }

        return result.toString();
    }

    private static String canonicalizeIpv6(
            String value
    ) {
        if (!value.contains(":")
                || value.contains("*")
                || value.contains("%")) {
            return null;
        }

        try {
            InetAddress address =
                    InetAddress.getByName(value);

            return address
                    .getHostAddress()
                    .toLowerCase(Locale.ROOT);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean looksLikeIpv4Pattern(
            String value
    ) {
        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.equals("*")) {
                continue;
            }

            if (part.isEmpty()) {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(
                        part.charAt(i)
                )) {
                    return false;
                }
            }
        }

        return true;
    }

    private static boolean isValidHostnamePattern(
            String value
    ) {
        if (value.isEmpty()
                || value.length() > 253
                || value.startsWith(".")
                || value.endsWith(".")
                || value.contains("..")
                || value.contains(":")) {
            return false;
        }

        String[] labels = value.split("\\.", -1);

        for (String label : labels) {
            if (label.equals("*")) {
                continue;
            }

            if (label.isEmpty()
                    || label.length() > 63
                    || label.startsWith("-")
                    || label.endsWith("-")) {
                return false;
            }

            for (int i = 0; i < label.length(); i++) {
                char character = label.charAt(i);

                if (!((character >= 'a'
                        && character <= 'z')
                        || (character >= '0'
                        && character <= '9')
                        || character == '-')) {
                    return false;
                }
            }
        }

        return true;
    }

    private static Pattern compileHostnameWildcard(
            String wildcard
    ) {
        String[] labels = wildcard.split("\\.");

        StringBuilder regex =
                new StringBuilder("^");

        for (int i = 0; i < labels.length; i++) {
            if (i > 0) {
                regex.append("\\.");
            }

            if (labels[i].equals("*")) {
                regex.append("[^.]+");
            } else {
                regex.append(
                        Pattern.quote(labels[i])
                );
            }
        }

        regex.append("$");

        return Pattern.compile(
                regex.toString()
        );
    }

    private boolean isAllowed(
            InboundConnection connection
    ) {
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
                    .map(host ->
                            isAllowedHost(
                                    host,
                                    current
                            )
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

        for (Pattern pattern :
                current.wildcardPatterns()) {

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
            return sanitizeForLog(
                    connection
                            .getRawVirtualHost()
                            .orElse("<unknown>")
            );
        } catch (RuntimeException e) {
            return "<unknown>";
        }
    }

    private static String sanitizeForLog(
            String value
    ) {
        StringBuilder result =
                new StringBuilder(value.length());

        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);

            if (Character.isISOControl(character)) {
                result.append('?');
            } else {
                result.append(character);
            }
        }

        return result.toString();
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
        if (silentCloseUnavailable.get()) {
            return false;
        }

        try {
            Method delegatedMethod =
                    delegatedConnectionMethod;

            if (delegatedMethod == null
                    || !delegatedMethod
                    .getDeclaringClass()
                    .isAssignableFrom(
                            connection.getClass()
                    )) {

                delegatedMethod =
                        findDeclaredMethod(
                                connection.getClass(),
                                "delegatedConnection"
                        );

                delegatedMethod.setAccessible(true);
                delegatedConnectionMethod =
                        delegatedMethod;
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
                            minecraftConnection
                                    .getClass()
                    )) {

                closeMethod =
                        minecraftConnection
                                .getClass()
                                .getMethod(
                                        "close",
                                        boolean.class
                                );

                closeConnectionMethod =
                        closeMethod;
            }

            closeMethod.invoke(
                    minecraftConnection,
                    true
            );

            return true;
        } catch (ReflectiveOperationException
                 | RuntimeException e) {

            if (silentCloseUnavailable
                    .compareAndSet(
                            false,
                            true
                    )) {

                logger.error(
                        "Host Gate silent close is unavailable; "
                                + "falling back to Minecraft disconnects "
                                + "until the proxy is restarted",
                        e
                );
            }

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

        if (current.rejectMode()
                == RejectMode.DISCONNECT) {

            event.setResult(
                    PreLoginEvent
                            .PreLoginComponentResult
                            .denied(
                                    Component.text(
                                            current.disconnectMessage()
                                    )
                            )
            );

            return;
        }

        if (closeSilently(
                event.getConnection()
        )) {
            return;
        }

        event.setResult(
                PreLoginEvent
                        .PreLoginComponentResult
                        .denied(
                                Component.text(
                                        current.disconnectMessage()
                                )
                        )
        );
    }

    private final class HostGateCommand
            implements SimpleCommand {

        @Override
        public void execute(
                Invocation invocation
        ) {
            if (!invocation
                    .source()
                    .hasPermission(
                            RELOAD_PERMISSION
                    )) {

                invocation
                        .source()
                        .sendMessage(
                                Component.text(
                                        "You do not have permission "
                                                + "to use this command."
                                )
                        );

                return;
            }

            String[] arguments =
                    invocation.arguments();

            if (arguments.length != 1
                    || !arguments[0]
                    .equalsIgnoreCase("reload")) {

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
                                        "Host Gate configuration could not "
                                                + "be loaded. Check the proxy log."
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
                    .hasPermission(
                            RELOAD_PERMISSION
                    )) {
                return List.of();
            }

            String[] arguments =
                    invocation.arguments();

            if (arguments.length == 0) {
                return List.of("reload");
            }

            if (arguments.length == 1
                    && "reload".startsWith(
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
