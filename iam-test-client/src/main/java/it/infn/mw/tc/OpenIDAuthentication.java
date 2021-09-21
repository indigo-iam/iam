package it.infn.mw.tc;

public class OpenIDAuthentication {

  private String issuer;
  private String sub;

  private String name;
  private String familyName;

  private String accessToken;
  private String refreshToken;
  private String idToken;

  private String idTokenClaims;

  private String userInfo;
  private String accessTokenClaims;

  public String getIssuer() {

    return issuer;
  }

  public String getSub() {

    return sub;
  }

  public String getAccessToken() {

    return accessToken;
  }

  public String getRefreshToken() {

    return refreshToken;
  }

  public String getIdToken() {

    return idToken;
  }

  public String getUserInfo() {

    return userInfo;
  }

  public String getName() {

    return name;
  }

  public String getFamilyName() {

    return familyName;
  }

  public String getAccessTokenClaims() {
    return accessTokenClaims;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public void setSub(String sub) {
    this.sub = sub;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setFamilyName(String familyName) {
    this.familyName = familyName;
  }

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  public void setRefreshToken(String refreshToken) {
    this.refreshToken = refreshToken;
  }

  public void setIdToken(String idToken) {
    this.idToken = idToken;
  }

  public void setUserInfo(String userInfo) {
    this.userInfo = userInfo;
  }

  public void setAccessTokenClaims(String accessTokenClaims) {
    this.accessTokenClaims = accessTokenClaims;
  }

  public String getIdTokenClaims() {
    return idTokenClaims;
  }

  public void setIdTokenClaims(String idTokenClaims) {
    this.idTokenClaims = idTokenClaims;
  }

}
