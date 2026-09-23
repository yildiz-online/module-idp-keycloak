package be.yildizgames.module.idp.keycloak;

import be.yildizgames.module.idp.IdpConfiguration;
import be.yildizgames.module.idp.IdpConnector;
import be.yildizgames.module.idp.IdpConnectorBuilder;

/**
 * @author Grégory Van den Borre
 */
public class KeycloakConnectorBuilder implements IdpConnectorBuilder {

    public KeycloakConnectorBuilder() {
        super();
    }

    @Override
    public IdpConnector buildIdpConnector(IdpConfiguration configuration) {
        return new KeycloakIdpConnector(configuration);
    }
}
