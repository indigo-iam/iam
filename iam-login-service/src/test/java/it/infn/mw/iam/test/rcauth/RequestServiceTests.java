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
package it.infn.mw.iam.test.rcauth;

import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.CERT_SUBJECT_CLAIM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.CLIENT_ID_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.CODE_RESPONSE_TYPE;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.DEFAULT_SCOPE;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.IDP_HINT_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.NONCE_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.RCAUTH_CTXT_SESSION_KEY;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.REDIRECT_URI_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.RESPONSE_TYPE_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.SCOPE_PARAM;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.STATE_PARAM;
import static it.infn.mw.iam.rcauth.RCAuthController.CALLBACK_PATH;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.rcauth.DefaultRcAuthRequestService;
import it.infn.mw.iam.rcauth.RCAuthAuthorizationResponse;
import it.infn.mw.iam.rcauth.RCAuthCertificateRequestor;
import it.infn.mw.iam.rcauth.RCAuthError;
import it.infn.mw.iam.rcauth.RCAuthExchangeContext;
import it.infn.mw.iam.rcauth.RCAuthProperties;
import it.infn.mw.iam.rcauth.RCAuthTokenRequestor;
import it.infn.mw.iam.rcauth.RCAuthTokenResponse;

@RunWith(MockitoJUnitRunner.class)
public class RequestServiceTests extends RCAuthTestSupport {


  @Mock
  IamProperties iamProps;

  @Mock
  RCAuthProperties props;

  @Mock
  ServerConfigurationService scs;

  @Mock
  HttpSession session;

  @Mock
  ServerConfiguration serverConfig;

  @Mock
  RCAuthTokenRequestor tokenRequestor;

  @Mock
  RCAuthCertificateRequestor certRequestor;

  @Mock
  RCAuthAuthorizationResponse authzResponse;

  @Mock
  RCAuthTokenResponse tokenResponse;

  @InjectMocks
  DefaultRcAuthRequestService service;

  @Before
  public void setup() {
    when(props.getKeySize()).thenReturn(512);
    when(props.getClientId()).thenReturn(CLIENT_ID);
    when(props.getIssuer()).thenReturn(ISSUER);
    when(scs.getServerConfiguration(Mockito.anyString())).thenReturn(serverConfig);
    when(serverConfig.getAuthorizationEndpointUri()).thenReturn(AUTHORIZATION_URI);
    when(iamProps.getBaseUrl()).thenReturn(IAM_BASE_URL);
    when(tokenRequestor.getAccessToken(Mockito.anyString())).thenReturn(tokenResponse);
    // This is just to return a well-formed X509 certificate, even if returing TEST_0
    // cert does not make sense in this context
    when(certRequestor.getCertificate(Mockito.any(), Mockito.any())).thenReturn(TEST_0_CERT);
  }


  @Test
  public void testUrlGeneration() throws UnsupportedEncodingException {
    String url = service.buildAuthorizationRequest(session);

    UriComponents uri = UriComponentsBuilder.fromHttpUrl(url).build();

    assertThat(uri.getHost(), is(RCAUTH_HOST));
    assertThat(uri.getScheme(), is(HTTPS));
    assertThat(uri.getQueryParams().getFirst(STATE_PARAM), notNullValue());
    assertThat(uri.getQueryParams().getFirst(NONCE_PARAM), notNullValue());
    assertThat(uri.getQueryParams().getFirst(SCOPE_PARAM),
        is(URLEncoder.encode(DEFAULT_SCOPE, "UTF-8")));
    assertThat(uri.getQueryParams().getFirst(RESPONSE_TYPE_PARAM), is(CODE_RESPONSE_TYPE));
    assertThat(uri.getQueryParams().getFirst(CLIENT_ID_PARAM), is(CLIENT_ID));
    assertThat(uri.getQueryParams().getFirst(REDIRECT_URI_PARAM),
        is(URLEncoder.encode(format("%s%s", IAM_BASE_URL, CALLBACK_PATH), "UTF-8")));

  }

  @Test
  public void testIdpHintIsRecognized() throws UnsupportedEncodingException {
    when(props.getIdpHint()).thenReturn(IAM_ENTITY_ID);
    String url = service.buildAuthorizationRequest(session);

    UriComponents uri = UriComponentsBuilder.fromHttpUrl(url).build();
    assertThat(uri.getHost(), is(RCAUTH_HOST));
    assertThat(uri.getScheme(), is(HTTPS));
    assertThat(uri.getQueryParams().getFirst(STATE_PARAM), notNullValue());
    assertThat(uri.getQueryParams().getFirst(NONCE_PARAM), notNullValue());
    assertThat(uri.getQueryParams().getFirst(SCOPE_PARAM),
        is(URLEncoder.encode(DEFAULT_SCOPE, "UTF-8")));
    assertThat(uri.getQueryParams().getFirst(RESPONSE_TYPE_PARAM), is(CODE_RESPONSE_TYPE));
    assertThat(uri.getQueryParams().getFirst(CLIENT_ID_PARAM), is(CLIENT_ID));
    assertThat(uri.getQueryParams().getFirst(IDP_HINT_PARAM), is(IAM_ENTITY_ID));
    assertThat(uri.getQueryParams().getFirst(REDIRECT_URI_PARAM),
        is(URLEncoder.encode(format("%s%s", IAM_BASE_URL, CALLBACK_PATH), "UTF-8")));

  }

  @Test(expected = RCAuthError.class)
  public void testHandleCodeResponseInvalidState() throws UnsupportedEncodingException {

    service.buildAuthorizationRequest(session);
    when(authzResponse.getState()).thenReturn("76321");

    ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<RCAuthExchangeContext> ctxtCaptor =
        ArgumentCaptor.forClass(RCAuthExchangeContext.class);

    verify(session).setAttribute(keyCaptor.capture(), ctxtCaptor.capture());
    when(session.getAttribute(RCAUTH_CTXT_SESSION_KEY)).thenReturn(ctxtCaptor.getValue());
    try {
      service.handleAuthorizationCodeResponse(session, authzResponse);
    } catch (RCAuthError e) {
      assertThat(e.getMessage(), containsString("state parameter mismatch"));
      throw e;
    }
  }

  @Test(expected = RCAuthError.class)
  public void testHandleCodeResponseContextNotFound() throws UnsupportedEncodingException {

    // when(authzResponse.getState()).thenReturn("76321");

    try {
      service.handleAuthorizationCodeResponse(session, authzResponse);
    } catch (RCAuthError e) {
      assertThat(e.getMessage(), containsString("RCAuth context not found"));
      throw e;
    }
  }

  @Test(expected = RCAuthError.class)
  public void testHandleCodeResponseParseError() throws UnsupportedEncodingException {
    service.buildAuthorizationRequest(session);

    ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<RCAuthExchangeContext> ctxtCaptor =
        ArgumentCaptor.forClass(RCAuthExchangeContext.class);

    verify(session).setAttribute(keyCaptor.capture(), ctxtCaptor.capture());

    when(session.getAttribute(RCAUTH_CTXT_SESSION_KEY)).thenReturn(ctxtCaptor.getValue());
    when(authzResponse.getState()).thenReturn(ctxtCaptor.getValue().getState());
    when(authzResponse.getCode()).thenReturn("code");

    when(tokenResponse.getIdToken()).thenReturn("fake-id-token");

    try {
      service.handleAuthorizationCodeResponse(session, authzResponse);
    } catch (RCAuthError e) {
      assertThat(e.getMessage(), containsString("Error parsing id token"));
      throw e;
    }
  }


  @Test(expected = RCAuthError.class)
  public void testHandleCodeResponseMissingCertificateSubjectClaim()
      throws UnsupportedEncodingException, JOSEException {

    service.buildAuthorizationRequest(session);

    ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<RCAuthExchangeContext> ctxtCaptor =
        ArgumentCaptor.forClass(RCAuthExchangeContext.class);

    verify(session).setAttribute(keyCaptor.capture(), ctxtCaptor.capture());

    when(session.getAttribute(RCAUTH_CTXT_SESSION_KEY)).thenReturn(ctxtCaptor.getValue());
    when(authzResponse.getState()).thenReturn(ctxtCaptor.getValue().getState());
    when(authzResponse.getCode()).thenReturn("code");

    String idToken = tokenBuilder.sub(SUB).issuer(ISSUER).build();

    when(tokenResponse.getIdToken()).thenReturn(idToken);

    try {
      service.handleAuthorizationCodeResponse(session, authzResponse);
    } catch (RCAuthError e) {
      assertThat(e.getMessage(), containsString("Certificate subject claim not found in id token"));
      throw e;
    }
  }

  @Test
  public void testHandleCodeResponseOk() throws UnsupportedEncodingException, JOSEException {

    service.buildAuthorizationRequest(session);

    ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<RCAuthExchangeContext> ctxtCaptor =
        ArgumentCaptor.forClass(RCAuthExchangeContext.class);

    verify(session).setAttribute(keyCaptor.capture(), ctxtCaptor.capture());

    when(session.getAttribute(RCAUTH_CTXT_SESSION_KEY)).thenReturn(ctxtCaptor.getValue());
    when(authzResponse.getState()).thenReturn(ctxtCaptor.getValue().getState());
    when(authzResponse.getCode()).thenReturn("code");

    String idToken =
        tokenBuilder.sub(SUB).issuer(ISSUER).customClaim(CERT_SUBJECT_CLAIM, "CN=Example").build();

    when(tokenResponse.getIdToken()).thenReturn(idToken);

    service.handleAuthorizationCodeResponse(session, authzResponse);

  }
}
