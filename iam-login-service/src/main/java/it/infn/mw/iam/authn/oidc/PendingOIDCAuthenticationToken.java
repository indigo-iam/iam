package it.infn.mw.iam.authn.oidc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.ParseException;
import java.util.ArrayList;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

public class PendingOIDCAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 22100073066377804L;

    private final ImmutableMap<String, String> principal;
    private final String accessTokenValue;
    private final String refreshTokenValue;
    private transient JWT idToken;
    private final String issuer;
    private final String sub;

    private final transient ServerConfiguration serverConfiguration;

    /**
     * Constructs OIDCAuthenticationToken for use as a data shuttle from the filter to the auth provider.
     *
     * Set to not-authenticated.
     *
     * Constructs a Principal out of the subject and issuer.
     * @param sub
     * @param idToken
     */
    public PendingOIDCAuthenticationToken (String subject, String issuer,
            ServerConfiguration serverConfiguration,
            JWT idToken, String accessTokenValue, String refreshTokenValue) {

        super(new ArrayList<GrantedAuthority>(0));

        this.principal = ImmutableMap.of("sub", subject, "iss", issuer);
        this.sub = subject;
        this.issuer = issuer;
        this.idToken = idToken;
        this.accessTokenValue = accessTokenValue;
        this.refreshTokenValue = refreshTokenValue;

        this.serverConfiguration = serverConfiguration;


        setAuthenticated(false);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.security.core.Authentication#getCredentials()
     */
    @Override
    public Object getCredentials() {
        return accessTokenValue;
    }

    /**
     * Get the principal of this object, an immutable map of the subject and issuer.
     */
    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getSub() {
        return sub;
    }

    /**
     * @return the idTokenValue
     */
    public JWT getIdToken() {
        return idToken;
    }

    /**
     * @return the accessTokenValue
     */
    public String getAccessTokenValue() {
        return accessTokenValue;
    }

    /**
     * @return the refreshTokenValue
     */
    public String getRefreshTokenValue() {
        return refreshTokenValue;
    }

    /**
     * @return the serverConfiguration
     */
    public ServerConfiguration getServerConfiguration() {
        return serverConfiguration;
    }

    /**
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /*
     * Custom serialization to handle the JSON object
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        if (idToken == null) {
            out.writeObject(null);
        } else {
            out.writeObject(idToken.serialize());
        }
    }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException, ParseException {
        in.defaultReadObject();
        Object o = in.readObject();
        if (o != null) {
            idToken = JWTParser.parse((String)o);
        }
    }

}
