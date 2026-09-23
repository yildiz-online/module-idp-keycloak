package be.yildizgames.module.idp.keycloak;

import be.yildizgames.module.idp.AuthenticationFlowResult;
import be.yildizgames.module.idp.IdpConfiguration;
import be.yildizgames.module.idp.IdpConnector;
import be.yildizgames.module.idp.UserSession;
import be.yildizgames.module.idp.keycloak.internal.SessionManager;

import java.awt.Desktop;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * @author Grégory Van den Borre
 */
public class KeycloakIdpConnector implements IdpConnector {

    private final KeycloakAuth keycloakAuth;
    private final SessionManager sessionManager;
    private final Map<UUID, CallbackServer> runningServer = new HashMap<>();

    public KeycloakIdpConnector(IdpConfiguration configuration) {
        this.sessionManager = new SessionManager();
        this.keycloakAuth = new KeycloakAuth(configuration);
    }

    @Override
    public final void login(UUID subject, Consumer<AuthenticationFlowResult> callback) {
        if(!this.sessionManager.isAuthenticated(subject)) {
            System.getLogger(this.getClass().getName()).log(System.Logger.Level.INFO, "User " + subject + " is not authenticated, opening connection window.");
            try {
                if(this.runningServer.containsKey(subject)) {
                    System.getLogger(this.getClass().getName()).log(System.Logger.Level.WARNING,"Callback server already running for account " + subject + ", closing it.");
                    this.runningServer.remove(subject).stop();
                }
                var codeVerifier = PkceUtil.generateCodeVerifier();
                var codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);
                var state = UUID.randomUUID().toString();
                var callbackServer = new CallbackServer(7890, cb -> new Thread(() -> {
                    try {
                        var tokens = keycloakAuth.exchangeCodeForTokens(cb.code(), codeVerifier);
                        var userId = extractUserIdFromIdToken(tokens.idToken().raw());
                        var username = extractUsernameFromIdToken(tokens.idToken().raw());
                        var session = sessionManager.addSession(userId, username, tokens);
                        callback.accept(AuthenticationFlowResult.success(session));
                    } catch (Exception ex) {
                        callback.accept(AuthenticationFlowResult.error(ex));
                    }
                }).start());
                this.runningServer.put(subject, callbackServer);
                callbackServer.start();
                var authUrl = keycloakAuth.buildAuthorizationUrl(state, codeChallenge);
                Desktop.getDesktop().browse(URI.create(authUrl));
            } catch (Exception ex) {
                System.getLogger(this.getClass().getName()).log(System.Logger.Level.ERROR, "", ex);
                callback.accept(AuthenticationFlowResult.error(ex));
            }
        }
    }

    @Override
    public final void shutdownCallbackServer(UUID key) {
        this.runningServer.remove(key).stop();
    }

    @Override
    public final boolean isAuthenticated(UUID id) {
        return this.sessionManager.isAuthenticated(id);
    }

    @Override
    public final UserSession getSession(UUID value) {
        return this.sessionManager.getSession(value);
    }

    private UUID extractUserIdFromIdToken(String idToken) {
        String payload = decodeJwtPayload(idToken);
        return UUID.fromString(Objects.requireNonNull(extractClaim(payload, "sub")));
    }

    private String extractUsernameFromIdToken(String idToken) {
        var payload = decodeJwtPayload(idToken);
        var username = extractClaim(payload, "preferred_username");
        if (username == null) {
            username = extractClaim(payload, "name");
        }
        return username;
    }

    private String decodeJwtPayload(String jwt) {
        var parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT");
        }
        var payload = parts[1];
        var decoded = Base64.getUrlDecoder().decode(payload);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static final Pattern CLAIM_PATTERN = Pattern.compile("\"(\\w+)\"\\s*:\\s*\"([^\"]*)\"");

    private String extractClaim(String json, String claimName) {
        var matcher = CLAIM_PATTERN.matcher(json);
        while (matcher.find()) {
            var name = matcher.group(1);
            if (claimName.equals(name)) {
                return matcher.group(2);
            }
        }
        return null;
    }
}
