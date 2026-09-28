package be.yildizgames.module.idp.keycloak;

import be.yildizgames.module.http.HttpClientBuilder;
import be.yildizgames.module.idp.IdpConfiguration;
import be.yildizgames.module.jwt.IdToken;
import be.yildizgames.module.jwt.Tokens;
import be.yildizgames.module.serialization.Serializer;
import be.yildizgames.module.serialization.SerializerBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * @author Grégory Van den Borre
 */
public class KeycloakAuth {

    private final IdpConfiguration configuration;

    private final Serializer<String> serializer = SerializerBuilder.provideJson();

    private final be.yildizgames.module.http.HttpClient client = HttpClientBuilder.provide().buildHttpClient();

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

        var response = client.postText(
                this.configuration.tokenEndpoint(),
                body,
                "application/x-www-form-urlencoded");

        var json = this.serializer.readObject(response.body().orElseThrow(), ReceivedTokens.class);
        long now = System.currentTimeMillis() / 1000;

        return new Tokens(
                json.access_token,
                json.refresh_token,
                new IdToken(json.id_token),
                json.expires_in,
                now
        );
    }

    private static class ReceivedTokens {

        private String access_token;

        private String refresh_token;

        private String id_token;

        private long expires_in;
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
