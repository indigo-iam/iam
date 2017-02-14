package it.infn.mw.iam.test;

import static com.jayway.restassured.RestAssured.given;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.config.ObjectMapperConfig;
import com.jayway.restassured.config.RestAssuredConfig;
import com.jayway.restassured.mapper.factory.Jackson2ObjectMapperFactory;
import com.jayway.restassured.specification.RequestSpecification;

import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimUser;

public class TestUtils {

  public static final int TOTAL_USERS_COUNT = 253;
  public static final String CLIENT_CRED_GRANT_CLIENT_ID = "client-cred";
  public static final String CLIENT_CRED_GRANT_CLIENT_SECRET = "secret";
  public static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";
  public static final String PASSWORD_GRANT_CLIENT_SECRET = "secret";

  public static final List<SshKey> sshKeys = new ArrayList<SshKey>();
  public static final List<X509Cert> x509Certs = new ArrayList<X509Cert>();
  public static final List<SamlId> samlIds = new ArrayList<SamlId>();
  public static final List<OidcId> oidcIds = new ArrayList<OidcId>();

  static {

    SshKey sshKey = new SshKey();
    sshKey.fingerprintSHA256 = "iXUu+MjanRMxt+Sd9qkw7J2y7xYP/FRodd4lxHnc7zA=";
    sshKey.fingerprintMD5Formatted = "d6:cc:0f:af:ed:c4:aa:5e:fa:40:52:3e:f1:11:db:e0";
    sshKey.fingerprintMDS = "d6cc0fafedc4aa5efa40523ef111dbe0";
    sshKey.key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC4tjz4mfMLvJsM8RXIgdRYPBhH//VXLXbeLb"
        + "UsJpm5ARIQPY6Gu1befPA3jqKacvdcBrMsYGiMp/DOhpkAwWclSnzMdvYLbYWkrOP"
        + "wBVrRh7lvFtXFLaQZ6do4uMZHb5zU2ViTFacrJ6zJ/GLltjk4nBea7Z4qHaQdWou3"
        + "Fk/108oMQGx7jqW44m+TA+HYo6rEbVWbimWVXyyiKchO2LTLKUbK6GBSWJiItezwA"
        + "WR3KKs3FXKRmbJDiKESh3mDccJidfkjzNLPyDf3JHI2b/C/mcvtJsoAtkIWuVll2B"
        + "hBBiqkYt3tX2llZCYGtF7rZOYTsqhw+LPnsJtsX+W7e4iN";
    sshKeys.add(sshKey);

    sshKey = new SshKey();
    sshKey.fingerprintSHA256 = "dowJH1al1DJII+i7DYux1BGQkx3P+XVpaz3TIX5zt5Y=";
    sshKey.fingerprintMD5Formatted = "26:5a:f5:c5:56:42:1a:4e:94:32:f6:5e:48:b3:7d:91";
    sshKey.fingerprintMDS = "265af5c556421a4e9432f65e48b37d91";
    sshKey.key = "AAAAB3NzaC1yc2EAAAABIwAAAQEAxL6nllg/rMURT2QTy4MGj0gxYQ6sxcqCde5or"
        + "LBs4rjIogo9bL7+HFLt6FHpCQbZ0CXakoL2M7PmXbFdwlD4Yw4ye4VxEaW3J1eNzR"
        + "MWMGNTaAlcGiQqDuS/SsxI6SOlp/kfXQprDn2MnED1jIQHQq5pm25wKpKYeUBAaC6"
        + "hvA4OlE39YpMCsVPEM3BhkR7F51I/60+5jV5P/g0arCnZKYJOnLmNpYc86ry8yydQ"
        + "MvD5HFBjRR8GRfvTU/0UcVtNsa1PzHTD7+lTA7iwDHX4cfe+4o38C850zU9yUMV+S"
        + "nlLMJhwBiCxaaqeU0SdBbG+nCL47drSlSvv85+baXftSw==";
    sshKeys.add(sshKey);

    X509Cert x509Cert = new X509Cert();
    x509Cert.display = "Personal Certificate";
    x509Cert.certificate = "MIIEWDCCA0CgAwIBAgIDAII4MA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNVBAYTAklU"
        + "MQ0wCwYDVQQKEwRJTkZOMRAwDgYDVQQDEwdJTkZOIENBMB4XDTE1MDUxODEzNTQx"
        + "NFoXDTE2MDUxNzEzNTQxNFowZDELMAkGA1UEBhMCSVQxDTALBgNVBAoTBElORk4x"
        + "HTAbBgNVBAsTFFBlcnNvbmFsIENlcnRpZmljYXRlMQ0wCwYDVQQHEwRDTkFGMRgw"
        + "FgYDVQQDEw9FbnJpY28gVmlhbmVsbG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"
        + "ggEKAoIBAQDf74gCX/5D7HAKlI9u+vMy4R8uYvtZp60L401zOuDHc0sKPCq2sU8N"
        + "IB8cNOC+69h+hPqbU8gcleXZ0T3KOy3NPrU7CFaOxzsCVAoDcLeKFlCMu4X1OK0V"
        + "NPq7+fgJ1cVdsJ4StHl3oTtQPCoU6NNly8HJIufVjat2IgjNHdMHINs5IcxpTmE5"
        + "OGae3reOfRBtqBr8UvyiTwHEEll6JpdbKjzjrcHBoOdFZTiwR18fO+B8MZLOjXSk"
        + "OEG5p5K8y4UOkHQeqooKgW0tn7dvCxQfuu5TGYUmK6pwjcxzcnSE9U4abFh5/oD1"
        + "PqjoCGtlvnl9nGrhAFD+qa5zq6SrgWsNAgMBAAGjggFHMIIBQzAMBgNVHRMBAf8E"
        + "AjAAMA4GA1UdDwEB/wQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH"
        + "AwQwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL3NlY3VyaXR5LmZpLmluZm4uaXQv"
        + "Q0EvSU5GTkNBX2NybC5kZXIwJQYDVR0gBB4wHDAMBgorBgEEAdEjCgEHMAwGCiqG"
        + "SIb3TAUCAgEwHQYDVR0OBBYEFIQEiwCbKssJqSBNMziZtu54ZQRCMFYGA1UdIwRP"
        + "ME2AFNFi87N3csgu+/J5Gm83TiefE9UgoTKkMDAuMQswCQYDVQQGEwJJVDENMAsG"
        + "A1UEChMESU5GTjEQMA4GA1UEAxMHSU5GTiBDQYIBADAnBgNVHREEIDAegRxlbnJp"
        + "Y28udmlhbmVsbG9AY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBCwUAA4IBAQBfhv9P"
        + "4bYo7lVRYjHrxreKVaEyujzPZFowZPYMz0e/lPcdqh9TIoDBbhy7/PXiTVqQEniZ"
        + "fU1Nso4rqBj8Qy609Y60PEFHhfLnjhvd/d+pXu6F1QTzUMwA2k7z5M+ykh7L46/z"
        + "1vwvcdvCgtWZ+FedvLuKh7miTCfxEIRLcpRPggbC856BSKet7jPdkMxkUwbFa34Z"
        + "qOuDQ6MvcrFA/lLgqN1c1OoE9tnf/uyOjVYq8hyXqOAhi2heE1e+s4o3/PQsaP5x"
        + "LetVho/J33BExHo+hCMt1rN89DO5qU7FFijLlbmOZROacpjkPNn2V4wkd5WeX2dm" + "b6UoBRqPsAiQL0mY";
    x509Certs.add(x509Cert);

    x509Cert = new X509Cert();
    x509Cert.display = "Personal Certificate";
    x509Cert.certificate = "MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDE"
        + "MMAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzNF"
        + "oXDTIyMDkyNDE1MzkzNFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOM"
        + "AwGA1UEAxMFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK"
        + "xtrwhoZ27SxxISjlRqWmBWB6U+N/xW2kS1uUfrQRav6auVtmtEW45J44VTi3WW6"
        + "Y113RBwmS6oW+3lzyBBZVPqnhV9/VkTxLp83gGVVvHATgGgkjeTxIsOE+TkPKAo"
        + "ZJ/QFcCfPh3WdZ3ANI14WYkAM9VXsSbh2okCsWGa4o6pzt3Pt1zKkyO4PW0cBkl"
        + "etDImJK2vufuDVNm7Iz/y3/8pY8p3MoiwbF/PdSba7XQAxBWUJMoaleh8xy8HSR"
        + "On7tF2alxoDLH4QWhp6UDn2rvOWseBqUMPXFjsUi1/rkw1oHAjMroTk5lL15GI0"
        + "LGd5dTVopkKXFbTTYxSkPz1MLAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBg"
        + "NVHQ4EFgQUfLdB5+jO9LyWN2/VCNYgMa0jvHEwDgYDVR0PAQH/BAQDAgXgMD4GA"
        + "1UdJQQ3MDUGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4"
        + "QgQBBggrBgEFBQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjA"
        + "nBgNVHREEIDAegRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSI"
        + "b3DQEBBQUAA4IBAQANYtWXetheSeVpCfnId9TkKyKTAp8RahNZl4XFrWWn2S9We"
        + "7ACK/G7u1DebJYxd8POo8ClscoXyTO2BzHHZLxauEKIzUv7g2GehI+SckfZdjFy"
        + "RXjD0+wMGwzX7MDuSL3CG2aWsYpkBnj6BMlr0P3kZEMqV5t2+2Tj0+aXppBPVwz"
        + "JwRhnrSJiO5WIZAZf49YhMn61sQIrepvhrKEUR4XVorH2Bj8ek1/iLlgcmFMBOd"
        + "s+PrehSRR8Gn0IjlEgC68EY6KPE+FKySuS7Ur7lTAjNdddfdAgKV6hJyST6/dx8"
        + "ymIkb8nxCPnxCcT2I2NvDxcPMc/wmnMa+smNal0sJ6m";
    x509Certs.add(x509Cert);

    SamlId samlId = new SamlId();
    samlId.idpId = "Saml IDP ID";
    samlId.userId = "User1 ID";
    samlIds.add(samlId);

    samlId = new SamlId();
    samlId.idpId = "Saml IDP ID";
    samlId.userId = "User2 ID";
    samlIds.add(samlId);

    OidcId oidcId = new OidcId();
    oidcId.issuer = "Oidc ID Issuer";
    oidcId.subject = "User1 subject";
    oidcIds.add(oidcId);

    oidcId = new OidcId();
    oidcId.issuer = "Oidc ID Issuer";
    oidcId.subject = "User2 subject";
    oidcIds.add(oidcId);
  }

  public static ObjectMapper createJacksonObjectMapper() {

    FilterProvider filters = new SimpleFilterProvider().setFailOnUnknownId(false);

    ObjectMapper mapper = new ObjectMapper();
    mapper.setFilterProvider(filters);
    return mapper;

  }

  public static Jackson2ObjectMapperFactory getJacksonObjectMapperFactory() {

    return new Jackson2ObjectMapperFactory() {

      @Override
      public ObjectMapper create(@SuppressWarnings("rawtypes") Class cls, String charset) {

        return createJacksonObjectMapper();
      }
    };
  }

  public static void initRestAssured() {

    RestAssured.config = RestAssuredConfig.config().objectMapperConfig(
        new ObjectMapperConfig().jackson2ObjectMapperFactory(getJacksonObjectMapperFactory()));

  }

  public static ScimMemberRef getMemberRef(ScimUser user) {

    return ScimMemberRef.builder()
      .display(user.getDisplayName())
      .ref(user.getMeta().getLocation())
      .value(user.getId())
      .build();
  }

  public static List<ScimMemberRef> buildScimMemberRefList(List<ScimUser> users) {

    List<ScimMemberRef> membersRefs = new ArrayList<ScimMemberRef>();
    for (ScimUser u : users) {
      membersRefs.add(getMemberRef(u));
    }
    return membersRefs;
  }

  public static String getAccessToken(String clientId, String clientSecret, String scope) {
    return clientCredentialsTokenGetter(clientId, clientSecret).scope(scope).getAccessToken();
  }

  public static AccessTokenGetter clientCredentialsTokenGetter(String clientId,
      String clientSecret) {
    return new AccessTokenGetter(clientId, clientSecret).grantType("client_credentials");
  }

  public static AccessTokenGetter clientCredentialsTokenGetter() {
    return new AccessTokenGetter(CLIENT_CRED_GRANT_CLIENT_ID, CLIENT_CRED_GRANT_CLIENT_SECRET)
      .grantType("client_credentials");
  }


  public static AccessTokenGetter passwordTokenGetter() {
    return new AccessTokenGetter(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET)
      .grantType("password");
  }

  public static AccessTokenGetter passwordTokenGetter(String clientId, String clientSecret) {
    return new AccessTokenGetter(clientId, clientSecret).grantType("password");
  }

  public static class AccessTokenGetter {
    private String clientId;
    private String clientSecret;
    private String scope;
    private String grantType;
    private String username;
    private String password;
    private String audience;

    private int port = 8080;

    public AccessTokenGetter(String clientId, String clientSecret) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
    }

    public AccessTokenGetter scope(String scope) {
      this.scope = scope;
      return this;
    }

    public AccessTokenGetter grantType(String grantType) {
      this.grantType = grantType;
      return this;
    }

    public AccessTokenGetter username(String username) {
      this.username = username;
      return this;
    }

    public AccessTokenGetter password(String password) {
      this.password = password;
      return this;
    }

    public AccessTokenGetter audience(String audience) {
      this.audience = audience;
      return this;
    }

    public String getAccessToken() {

      RequestSpecification req = given().port(port)
        .param("grant_type", grantType)
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("scope", scope);

      if (audience != null) {
        req.param("aud", audience);
      }

      if ("password".equals(grantType)) {
        req.param("username", username).param("password", password);
      }

      return req.when()
        .post("/token")
        .then()
        .log()
        .all(true)
        .statusCode(HttpStatus.OK.value())
        .extract()
        .path("access_token");
    }
  }
}
