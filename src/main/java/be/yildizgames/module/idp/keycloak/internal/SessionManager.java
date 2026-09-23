package be.yildizgames.module.idp.keycloak.internal;

import be.yildizgames.module.idp.UserSession;
import be.yildizgames.module.jwt.Tokens;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Grégory Van den Borre
 */
public class SessionManager {

    private final Map<UUID, UserSession> activeSessions = new ConcurrentHashMap<>();

    public UserSession addSession(UUID sub, String username, Tokens tokens) {
        var session = new UserSession(sub, username, tokens, LocalDateTime.now());
        this.activeSessions.put(sub, session);
        return session;
    }

    public final UserSession getSession(UUID sub) {
        return sub == null ? null : this.activeSessions.get(sub);
    }

    public final void removeSession(UUID sub) {
        this.activeSessions.remove(sub);
    }

    public boolean isAuthenticated(UUID sub) {
        return this.activeSessions.containsKey(sub);
    }
}
