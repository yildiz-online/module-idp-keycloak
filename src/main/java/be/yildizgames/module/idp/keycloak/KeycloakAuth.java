package be.yildizgames.module.idp.keycloak;

import be.yildizgames.module.idp.IdpConfiguration;
import be.yildizgames.module.jwt.IdToken;
import be.yildizgames.module.jwt.Tokens;
import org.json.JSONObject;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * @author Grégory Van den Borre
 */
public class KeycloakAuth {

    private final HttpClient httpClient = HttpClient.newHttpClient();

    private final IdpConfiguration configuration;

    public KeycloakAuth(IdpConfiguration configuration) {
        this.configuration = configuration;
    }

    public String buildAuthorizationUrl(String state, String codeChallenge) {
        var uriBuilder = UriBuilder.fromUri(this.configuration.authorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", this.configuration.clientId())
                .queryParam("redirect_uri", this.configuration.redirectUri())
                .queryParam("scope", String.join(" ", this.configuration.scopes()))
                .queryParam("state", state)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256");

        return uriBuilder.build();
    }

    public Tokens exchangeCodeForTokens(String code, String codeVerifier) throws Exception {
        var body = new URLEncodedFormBuilder()
                .add("grant_type", "authorization_code")
                .add("client_id", this.configuration.clientId())
                .add("redirect_uri", this.configuration.redirectUri())
                .add("code", code)
                .add("code_verifier", codeVerifier)
                .build();

        var request = HttpRequest.newBuilder()
                .uri(URI.create(this.configuration.tokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Token endpoint error: " + response.statusCode() + " - " + response.body());
        }

        var json = new JSONObject(response.body());
        long now = System.currentTimeMillis() / 1000;

        return new Tokens(
                json.getString("access_token"),
                json.getString("refresh_token"),
                new IdToken(json.getString("id_token")),
                json.getLong("expires_in"),
                now
        );
    }

    private static class URLEncodedFormBuilder {
        private final StringBuilder sb = new StringBuilder();
        private boolean first = true;

        public URLEncodedFormBuilder add(String key, String value) {
            if (!first) sb.append('&');
            first = false;
            sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
            return this;
        }

        public String build() {
            return sb.toString();
        }
    }
}
