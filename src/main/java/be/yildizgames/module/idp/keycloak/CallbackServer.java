package be.yildizgames.module.idp.keycloak;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Grégory Van den Borre
 */
public class CallbackServer {

    private final int port;
    private final Consumer<AuthCallback> onCallback;
    private HttpServer server;

    public record AuthCallback(String code, String state) {
    }

    public CallbackServer(int port, Consumer<AuthCallback> onCallback) {
        this.port = port;
        this.onCallback = onCallback;
    }

    public void start() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.createContext("/callback").setHandler(exchange -> {
            try {
                var query = exchange.getRequestURI().getQuery();
                var params = parseQuery(query);
                var code = params.get("code");
                var state = params.get("state");
                if (code != null) {
                    this.onCallback.accept(new AuthCallback(code, state));
                }
                var html = """
                        <html><body>
                        <h2>Authentification réussie</h2>
                        <p>Vous pouvez fermer cette fenêtre et revenir à l'application.</p>
                        </body></html>
                        """;

                var bytes = html.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.getResponseBody().flush();
                exchange.close();

            } catch (Exception e) {
                System.getLogger(this.getClass().getName()).log(System.Logger.Level.ERROR, "", e);
            }
        });
        server.setExecutor(null);
        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null) {
            return params;
        }
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }
}
