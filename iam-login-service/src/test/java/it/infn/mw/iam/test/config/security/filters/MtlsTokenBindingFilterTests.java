/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.config.security.filters;

import static it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder.CERT_HASH_FIELD_NAME;
import static it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder.CLIENT_CERT_HEADER;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.CNF;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.security.filters.MtlsTokenBindingFilter;

class MtlsTokenBindingFilterTests {

  private final MtlsTokenBindingFilter filter = new MtlsTokenBindingFilter();

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private FilterChain chain;

  private String certificate;
  private String thumbprint;

  @BeforeEach
  void setup() throws Exception {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    chain = mock(FilterChain.class);

    ClassPathResource resource =
        new ClassPathResource("x509/test0.cert.pem");

    try (var input = resource.getInputStream()) {
      certificate =
          new String(input.readAllBytes(), StandardCharsets.US_ASCII);
    }

    // Compute thumb-print. See X509Utils.getCertificateThumbprint()
    try (var input = resource.getInputStream()) {
      byte[] der = CertificateFactory.getInstance("X.509")
          .generateCertificate(input)
          .getEncoded();

      thumbprint = Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
    }
  }

  @Test
  void allowsRequestWithoutAuthorizationHeader() throws Exception {
    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void allowsNonBearerAuthentication() throws Exception {
    request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void allowsTokenWithoutConfirmationClaim() throws Exception {
    addBearerToken(null);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void allowsConfirmationClaimWithoutCertificateThumbprint() throws Exception {
    addBearerToken(Map.of("other", "value"));

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void allowsMatchingCertificate() throws Exception {
    addBearerToken(Map.of(CERT_HASH_FIELD_NAME, thumbprint));
    request.addHeader(CLIENT_CERT_HEADER, certificate);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void rejectsMissingCertificate() throws Exception {
    addBearerToken(Map.of(CERT_HASH_FIELD_NAME, thumbprint));

    assertUnauthorized("Missing mTLS certificate");
  }

  @Test
  void rejectsBlankCertificate() throws Exception {
    addBearerToken(Map.of(CERT_HASH_FIELD_NAME, thumbprint));
    request.addHeader(CLIENT_CERT_HEADER, "   ");

    assertUnauthorized("Missing mTLS certificate");
  }

  @Test
  void rejectsMismatchedCertificate() throws Exception {
    addBearerToken(Map.of(CERT_HASH_FIELD_NAME, "different-thumbprint"));
    request.addHeader(CLIENT_CERT_HEADER, certificate);

    assertUnauthorized("mTLS certificate thumbprint mismatch");
  }

  @Test
  void rejectsNullCertificateThumbprintClaim() throws Exception {
    Map<String, Object> cnf = new HashMap<>();
    cnf.put(CERT_HASH_FIELD_NAME, null);
    addBearerToken(cnf);

    assertUnauthorized("Missing mTLS certificate thumbprint claim");
  }

  @Test
  void rejectsMalformedBearerToken() throws Exception {
    request.addHeader("Authorization", "Bearer not-a-jwt");

    assertUnauthorized("Invalid access token format");
  }

  @Test
  void rejectsMalformedConfirmationClaim() throws Exception {
    addBearerToken("not-a-json-object");

    assertUnauthorized("Invalid access token format");
  }

  @Test
  void rejectsMalformedCertificate() throws Exception {
    addBearerToken(Map.of(CERT_HASH_FIELD_NAME, thumbprint));
    request.addHeader(CLIENT_CERT_HEADER, "%%%");

    assertUnauthorized("Missing mTLS certificate thumbprint");
  }

  private void assertUnauthorized(String message) throws Exception {
    filter.doFilter(request, response, chain);

    assertEquals(401, response.getStatus());
    assertEquals(message, response.getErrorMessage());
    verifyNoInteractions(chain);
  }

  private void addBearerToken(Object cnf) throws JOSEException {
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .subject("test-user");

    if (cnf != null) {
      claims.claim(CNF, cnf);
    }

    SignedJWT jwt = new SignedJWT(
        new JWSHeader(JWSAlgorithm.HS256), claims.build());

    // Test-only key: the tested filter does not verify signatures.
    jwt.sign(new MACSigner(new byte[32]));

    request.addHeader("Authorization", "Bearer " + jwt.serialize());
  }
}