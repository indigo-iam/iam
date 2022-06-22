package it.infn.mw.tc;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "iam")
public class IamClientApplicationProperties {

  public static class OidcClientProperties {
    String clientId;
    String clientSecret;
    List<String> redirectUris;
    String scope;

    public String getClientId() {
      return clientId;
    }

    public void setClientId(String clientId) {
      this.clientId = clientId;
    }

    public String getClientSecret() {
      return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUris() {
      return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
      this.redirectUris = redirectUris;
    }

    public String getScope() {
      return scope;
    }

    public void setScope(String scope) {
      this.scope = scope;
    }
  }


  public static class TlsConfig {
    String version = "TLSv1.2";

    boolean ignoreNamespaceChecks = false;
    boolean useGridTrustAnchors = true;
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public boolean isIgnoreNamespaceChecks() { return ignoreNamespaceChecks; }
    public void setIgnoreNamespaceChecks(boolean ignoreNamespaceChecks) {
      this.ignoreNamespaceChecks = ignoreNamespaceChecks;
    }
    public boolean isUseGridTrustAnchors() { return useGridTrustAnchors; }
    public void setUseGridTrustAnchors(boolean useGridTrustAnchors) {
      this.useGridTrustAnchors = useGridTrustAnchors;
    }
  }

  private String issuer;
  private String organizationName;
  private String extAuthnHint;
  private TlsConfig tls;

  private OidcClientProperties client;

  private boolean hideTokens = true;

  public String getIssuer() { return issuer; }

  public void setIssuer(String issuer) { this.issuer = issuer; }

  public String getExtAuthnHint() { return extAuthnHint; }

  public void setExtAuthnHint(String extAuthnHint) {
    this.extAuthnHint = extAuthnHint;
  }

  public TlsConfig getTls() { return tls; }

  public void setTls(TlsConfig tls) { this.tls = tls; }

  public String getOrganizationName() { return organizationName; }

  public void setOrganizationName(String organizationName) {
    this.organizationName = organizationName;
  }

  public boolean isHideTokens() {
    return hideTokens;
  }

  public void setHideTokens(boolean hideTokens) {
    this.hideTokens = hideTokens;
  }

  public OidcClientProperties getClient() {
    return client;
  }

  public void setClient(OidcClientProperties client) {
    this.client = client;
  }
}
