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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.ProviderNotFoundException;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamSamlId;

public class MultiFactorVerificationFilterTests {

  @Mock
  private AuthenticationManager authenticationManager;

  @Mock
  private AuthenticationSuccessHandler successHandler;

  @Mock
  private AuthenticationFailureHandler failureHandler;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private Authentication authentication;

  @InjectMocks
  private MultiFactorVerificationFilter multiFactorVerificationFilter;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @AfterEach
  public void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void testAuthenticationSuccess() throws Exception {
    Authentication mockAuth = mock(ExtendedAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    Authentication mockAuthenticatedToken =
        new ExtendedAuthenticationToken("username", null, new ArrayList<>());
    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenReturn(mockAuthenticatedToken);

    when(request.getMethod()).thenReturn("POST");
    when(request.getParameter("totp")).thenReturn("123456");

    Authentication result = multiFactorVerificationFilter.attemptAuthentication(request, response);

    assertNotNull(result);
    assertEquals(mockAuthenticatedToken, result);
  }

  @Test
  public void testOidcAuthenticationSuccess() throws Exception {
    OIDCAuthenticationToken mockOidcToken = mock(OIDCAuthenticationToken.class);
    Authentication mockAuth = mock(OidcExternalAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    Authentication mockAuthenticatedToken =
        new OidcExternalAuthenticationToken(mockOidcToken, "username", null);
    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenReturn(mockAuthenticatedToken);

    when(request.getMethod()).thenReturn("POST");
    when(request.getParameter("totp")).thenReturn("123456");

    Authentication result = multiFactorVerificationFilter.attemptAuthentication(request, response);

    assertNotNull(result);
    assertEquals(mockAuthenticatedToken, result);
  }

  @Test
  public void testSamlAuthenticationSuccess() throws Exception {
    ExpiringUsernameAuthenticationToken mockSamlToken =
        mock(ExpiringUsernameAuthenticationToken.class);
    Authentication mockAuth = mock(SamlExternalAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);
    IamSamlId samlId = mock(IamSamlId.class);

    Authentication mockAuthenticatedToken =
        new SamlExternalAuthenticationToken(samlId, mockSamlToken, null, "username", null, null);
    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenReturn(mockAuthenticatedToken);

    when(request.getMethod()).thenReturn("POST");
    when(request.getParameter("totp")).thenReturn("123456");

    Authentication result = multiFactorVerificationFilter.attemptAuthentication(request, response);

    assertNotNull(result);
    assertEquals(mockAuthenticatedToken, result);
  }

  @Test
  public void testAuthenticationFailureDueToUnsupportedAuthnMethod() throws Exception {
    Authentication mockAuth = mock(ExtendedAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    Authentication mockAuthenticatedToken =
        new ExtendedAuthenticationToken("username", null, new ArrayList<>());
    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenReturn(mockAuthenticatedToken);

    when(request.getMethod()).thenReturn("GET");

    assertThrows(AuthenticationServiceException.class,
        () -> multiFactorVerificationFilter.attemptAuthentication(request, response));
  }

  @Test
  public void testAuthenticationFailureDueToBadAuthn() throws Exception {
    Authentication mockAuth = mock(UsernamePasswordAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    Authentication mockAuthenticatedToken =
        new UsernamePasswordAuthenticationToken("username", null, new ArrayList<>());
    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenReturn(mockAuthenticatedToken);

    when(request.getMethod()).thenReturn("POST");

    assertThrows(AuthenticationServiceException.class,
        () -> multiFactorVerificationFilter.attemptAuthentication(request, response));
  }

  @Test
  public void testAuthenticationFailureDueToInvalidTOTP() throws Exception {
    Authentication mockAuth = mock(ExtendedAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    when(authenticationManager.authenticate(any(Authentication.class)))
      .thenThrow(new BadCredentialsException("Invalid TOTP"));

    when(request.getMethod()).thenReturn("POST");
    when(request.getParameter("totp")).thenReturn("wrong-totp");

    assertThrows(BadCredentialsException.class,
        () -> multiFactorVerificationFilter.attemptAuthentication(request, response));
  }

  @Test
  public void testAuthenticationFailureWhenTotpIsNull() {
    Authentication mockAuth = mock(ExtendedAuthenticationToken.class);
    when(mockAuth.getName()).thenReturn("username");

    SecurityContextHolder.getContext().setAuthentication(mockAuth);

    when(request.getMethod()).thenReturn("POST");
    when(request.getParameter("totp")).thenReturn(null);

    assertThrows(ProviderNotFoundException.class,
        () -> multiFactorVerificationFilter.attemptAuthentication(request, response));
  }
}

