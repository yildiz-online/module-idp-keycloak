package be.yildizgames.module.idp.keycloak;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Grégory Van den Borre
 */
public class UriBuilder {

    private final String baseUri;
    private final Map<String, String> queryParams = new LinkedHashMap<>();

    private UriBuilder(String baseUri) {
        this.baseUri = baseUri;
    }

    public static UriBuilder fromUri(String uri) {
        return new UriBuilder(uri);
    }

    public UriBuilder queryParam(String name, String value) {
        queryParams.put(name, value);
        return this;
    }

    public String build() {
        if (queryParams.isEmpty()) {
            return baseUri;
        }

        StringBuilder sb = new StringBuilder(baseUri);
        sb.append('?');

        boolean first = true;
        for (Map.Entry<String, String> e : queryParams.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            first = false;
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }

        return sb.toString();
    }
}
