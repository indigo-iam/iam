package it.infn.mw.iam.test.ext_authn.saml;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

import org.joda.time.DateTime;
import org.junit.Before;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.parser.SAMLObject;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;

import it.infn.mw.iam.test.util.saml.SamlAssertionBuilder;
import it.infn.mw.iam.test.util.saml.SamlResponseBuilder;

public class SamlExternalAuthenticationTestSupport {

  public static final String DEFAULT_IDP_ID = "https://idptestbed/idp/shibboleth";

  public static final String KEY_ALIAS = "iam-test";
  public static final String KS_PASSWORD = "iam-test";

  public static final String T1_NAMEID = "1234";
  public static final String T1_EPPN = "test-user@idptestbed";
  public static final String T1_EPUID = "123456@idptestbed";
  public static final String T1_GIVEN_NAME = "Test";
  public static final String T1_SN = "Saml User";
  public static final String T1_MAIL = "test-user@example.org";

  public static final String T2_NAMEID = "4567";
  public static final String T2_EPPN = "test-user-2@idptestbed";
  public static final String T2_EPUID = "78901@idptestbed";
  public static final String T2_GIVEN_NAME = "Test";
  public static final String T2_SN = "Saml User 2";
  public static final String T2_MAIL = "test-user-2@example.org";

  public static final String EXT_AUTHN_URL = "/iam/authn-info";

  @Autowired
  protected MetadataGenerator metadataGenerator;

  @Autowired
  protected ObjectMapper objectMapper;

  @Autowired
  protected WebApplicationContext context;

  protected MockMvc mvc;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();
  }

  public String samlLoginUrl() throws UnsupportedEncodingException {

    String defaultIdpUrl = String.format("/saml/login?idp=%s", DEFAULT_IDP_ID);

    return defaultIdpUrl;

  }

  public Credential serviceCredential()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {

    KeyStore ks = testKeyStore();
    JKSKeyManager keyManager =
        new JKSKeyManager(ks, ImmutableMap.of(KEY_ALIAS, KS_PASSWORD), KEY_ALIAS);

    return keyManager.getDefaultCredential();
  }

  public KeyStore testKeyStore()
      throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

    KeyStore ks = KeyStore.getInstance("JKS");

    ks.load(this.getClass().getResourceAsStream("/saml/idp-signing.jks"), "iam-test".toCharArray());
    return ks;

  }

  public SamlAssertionBuilder samlAssertionBuilder()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
    return new SamlAssertionBuilder(serviceCredential(), DEFAULT_IDP_ID);
  }

  public SamlResponseBuilder samlResponseBuilder()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
    return new SamlResponseBuilder(serviceCredential(), DEFAULT_IDP_ID);
  }


  public Response buildNoAudienceInvalidResponse(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {
    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    // This is invalid since no AUDIENCE is set
    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .eppn(T2_EPPN)
      .epuid(T2_EPUID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .mail(T2_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;

  }

  public Response buildNoAttributesInvalidResponse(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {
    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    // This is invalid since the assertion does not define
    // the minimum required attributes for the mapping
    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }

  public Response buildTest2Response(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {

    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .eppn(T2_EPPN)
      .epuid(T2_EPUID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .mail(T2_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }

  public Response buildTest1Response(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {

    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T1_NAMEID)
      .eppn(T1_EPPN)
      .epuid(T1_EPUID)
      .givenName(T1_GIVEN_NAME)
      .sn(T1_SN)
      .mail(T1_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }


  @SuppressWarnings("rawtypes")
  public AuthnRequest getAuthnRequestFromSession(MockHttpSession session) {
    @SuppressWarnings("unchecked")
    Map<String, SAMLObject<?>> samlStorage =
        (Map<String, SAMLObject<?>>) session.getAttribute("_springSamlStorageKey");

    String authnRequestKey = samlStorage.keySet().iterator().next();

    return (AuthnRequest) ((SAMLObject) samlStorage.get(authnRequestKey)).getObject();
  }
}
