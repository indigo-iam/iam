package it.infn.mw.tc;

import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "iam")
public class IamClientConfig extends RegisteredClient {

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

  String issuer;
  String organizationName;
  String extAuthnHint;
  TlsConfig tls;

  boolean hideTokens = true;

  public IamClientConfig() {
    setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
  }

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
}
