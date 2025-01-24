package it.infn.mw.iam.authn.oidc.model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.ParseException;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

public class OIDCAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final ImmutableMap<String, String> principal;
    private final String accessTokenValue;
    private final String refreshTokenValue;
    private transient JWT idToken;
    private final String issuer;
    private final String sub;

    private final UserInfo userInfo;

    /**
     * Constructs OIDCAuthenticationToken with a full set of authorities, marking this as authenticated.
     *
     * Set to authenticated.
     *
     * Constructs a Principal out of the subject and issuer.
     * @param subject
     * @param authorities
     * @param principal
     * @param idToken
     */
    public OIDCAuthenticationToken(String subject, String issuer,
            UserInfo userInfo, Collection<? extends GrantedAuthority> authorities,
            JWT idToken, String accessTokenValue, String refreshTokenValue) {

        super(authorities);

        this.principal = ImmutableMap.of("sub", subject, "iss", issuer);
        this.userInfo = userInfo;
        this.sub = subject;
        this.issuer = issuer;
        this.idToken = idToken;
        this.accessTokenValue = accessTokenValue;
        this.refreshTokenValue = refreshTokenValue;

        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return accessTokenValue;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getSub() {
        return sub;
    }

    public JWT getIdToken() {
        return idToken;
    }

    public String getAccessTokenValue() {
        return accessTokenValue;
    }

    public String getRefreshTokenValue() {
        return refreshTokenValue;
    }

    public String getIssuer() {
        return issuer;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

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
