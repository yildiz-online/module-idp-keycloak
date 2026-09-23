package be.yildizgames.module.idp.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author Grégory Van den Borre
 */
public class PkceUtil {

    private PkceUtil() {}

    public static String generateCodeVerifier() {
        var secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(codeVerifier);
    }

    public static String generateCodeChallenge(String codeVerifier) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        var sha256Hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(sha256Hash);
    }
}
