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
package it.infn.mw.iam.rcauth;

import static it.infn.mw.iam.rcauth.RCAuthController.CALLBACK_PATH;
import static it.infn.mw.iam.rcauth.x509.CertificateRequestUtil.buildCertificateRequest;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Optional;
import java.util.function.Supplier;

import javax.servlet.http.HttpSession;

import org.bouncycastle.operator.OperatorCreationException;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties;

@Service
@ConditionalOnProperty(name = "rcauth.enabled", havingValue = "true")
public class DefaultRcAuthRequestService implements RCAuthRequestService {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultRcAuthRequestService.class);

  public static final String HTTPS_SCHEME = "https";

  public static final String RCAUTH_CTXT_SESSION_KEY = "rcauth.ctxt";

  public static final String STATE_PARAM = "state";
  public static final String NONCE_PARAM = "nonce";
  public static final String PROMPT_PARAM = "prompt";
  public static final String CLIENT_ID_PARAM = "client_id";
  public static final String SCOPE_PARAM = "scope";
  public static final String RESPONSE_TYPE_PARAM = "response_type";
  public static final String REDIRECT_URI_PARAM = "redirect_uri";
  public static final String IDP_HINT_PARAM = "idphint";

  public static final String CERT_SUBJECT_CLAIM_NOT_FOUND_ERROR =
      "Certificate subject claim not found in id token!";
  public static final String CTXT_NOT_FOUND_ERROR = "RCAuth context not found in session!";
  public static final String STATE_MISMATCH_ERROR = "Invalid response: state parameter mismatch";
  public static final String DEFAULT_SCOPE = "openid profile email edu.uiuc.ncsa.myproxy.getcert";
  public static final String CODE_RESPONSE_TYPE = "code";

  public static final String CERT_SUBJECT_CLAIM = "cert_subject_dn";

  final IamProperties iamProperties;
  final RCAuthProperties properties;
  final ServerConfigurationService serverConfigService;
  final RCAuthTokenRequestor tokenRequestor;
  final RCAuthCertificateRequestor certRequestor;
  final SecureRandom rng;


  @Autowired
  public DefaultRcAuthRequestService(IamProperties iamProperties, RCAuthProperties properties,
      ServerConfigurationService scs, RCAuthTokenRequestor requestor,
      RCAuthCertificateRequestor certRequestor) {
    this.iamProperties = iamProperties;
    this.properties = properties;
    this.serverConfigService = scs;
    this.tokenRequestor = requestor;
    this.certRequestor = certRequestor;
    rng = new SecureRandom();
  }

  private Supplier<RCAuthError> certSubjectClaimNotFoundError() {
    return () -> new RCAuthError(CERT_SUBJECT_CLAIM_NOT_FOUND_ERROR);
  }

  private Supplier<RCAuthError> contextNotFoundError() {
    return () -> new RCAuthError(CTXT_NOT_FOUND_ERROR);
  }

  protected ServerConfiguration resolveServerConfiguration() {

    ServerConfiguration serverConfig =
        serverConfigService.getServerConfiguration(properties.getIssuer());

    if (isNull(serverConfig)) {
      throw new RCAuthError("Configuration not found for issuer: " + properties.getIssuer());
    }

    return serverConfig;
  }

  protected String urlEncodeUTF8String(String s) {
    try {
      return URLEncoder.encode(s, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      // will never happen
      throw new RCAuthError(e.getMessage(), e);
    }
  }

  @Override
  public String buildAuthorizationRequest(HttpSession session) {

    ServerConfiguration serverConfig = resolveServerConfiguration();

    UriComponentsBuilder uriBuilder =
        UriComponentsBuilder.fromHttpUrl(serverConfig.getAuthorizationEndpointUri());

    RCAuthExchangeContext ctxt = RCAuthExchangeContext.newContext();

    ctxt.setState(new BigInteger(50, rng).toString(16));
    ctxt.setNonce(new BigInteger(50, rng).toString(16));

    uriBuilder.queryParam(RESPONSE_TYPE_PARAM, CODE_RESPONSE_TYPE);
    uriBuilder.queryParam(STATE_PARAM, ctxt.getState());
    uriBuilder.queryParam(NONCE_PARAM, ctxt.getNonce());
    uriBuilder.queryParam(CLIENT_ID_PARAM, properties.getClientId());
    uriBuilder.queryParam(SCOPE_PARAM, urlEncodeUTF8String(DEFAULT_SCOPE));
    uriBuilder.queryParam(REDIRECT_URI_PARAM,
        urlEncodeUTF8String(format("%s%s", iamProperties.getBaseUrl(), CALLBACK_PATH)));

    if (!isNull(properties.getIdpHint())) {
      uriBuilder.queryParam(IDP_HINT_PARAM, urlEncodeUTF8String(properties.getIdpHint()));
    }

    ctxt.setAuthorizationUrl(uriBuilder.build().toUriString());

    session.setAttribute(RCAUTH_CTXT_SESSION_KEY, ctxt);
    return ctxt.getAuthorizationUrl();

  }

  protected Optional<String> getCertificateSubject(RCAuthTokenResponse tokenResponse) {
    SignedJWT idToken;

    try {
      idToken = SignedJWT.parse(tokenResponse.getIdToken());
      return Optional.ofNullable(idToken.getJWTClaimsSet().getStringClaim(CERT_SUBJECT_CLAIM));
    } catch (ParseException e) {
      throw new RCAuthError("Error parsing id token", e);
    }
  }

  protected Optional<RCAuthExchangeContext> getContextFromSession(HttpSession session) {
    return Optional
      .ofNullable((RCAuthExchangeContext) session.getAttribute(RCAUTH_CTXT_SESSION_KEY));
  }

  @Override
  public RCAuthExchangeContext handleAuthorizationCodeResponse(HttpSession session,
      RCAuthAuthorizationResponse response) {

    RCAuthExchangeContext ctxt = getContextFromSession(session).orElseThrow(contextNotFoundError());

    if (!ctxt.getState().equals(response.getState())) {
      throw new RCAuthError(STATE_MISMATCH_ERROR);
    }

    ctxt.setTokenResponse(tokenRequestor.getAccessToken(response.getCode()));

    String certSubject =
        getCertificateSubject(ctxt.getTokenResponse()).orElseThrow(certSubjectClaimNotFoundError());

    try {

      ctxt.setCertificateRequest(buildCertificateRequest(certSubject, properties.getKeySize()));
      ctxt.setCertificate(certRequestor.getCertificate(ctxt.getTokenResponse().getAccessToken(),
          ctxt.getCertificateRequest()));

      return ctxt;

    } catch (OperatorCreationException | IOException e) {
      LOG.error("Certificate request creation error: {}", e.getMessage(), e);
      throw new RCAuthError("Certificate request creation failed", e);
    }
  }
}
