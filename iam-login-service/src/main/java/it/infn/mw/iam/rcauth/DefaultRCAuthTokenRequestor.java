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
import static java.util.Objects.isNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.model.TokenEndpointErrorResponse;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.rcauth.oidc.RCAuthTokenResponseVerifier;
import it.infn.mw.iam.rcauth.util.AddContentTypeInterceptor;

@Component
@ConditionalOnProperty(name = "rcauth.enabled", havingValue = "true")
public class DefaultRCAuthTokenRequestor implements RCAuthTokenRequestor {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultRCAuthTokenRequestor.class);

  final RestTemplateFactory restFactory;
  final RCAuthProperties rcAuthProperties;
  final IamProperties iamProperties;
  final ServerConfigurationService serverConfigService;
  final ObjectMapper objectMapper;
  final RCAuthTokenResponseVerifier responseVerifier;
  
  @Autowired
  public DefaultRCAuthTokenRequestor(RestTemplateFactory restFactory, RCAuthProperties props,
      RCAuthTokenResponseVerifier verifier, IamProperties iamProps, ServerConfigurationService scs,
      ObjectMapper mapper) {
    this.restFactory = restFactory;
    this.rcAuthProperties = props;
    this.iamProperties = iamProps;
    this.serverConfigService = scs;
    this.objectMapper = mapper;
    this.responseVerifier = verifier;
  }

  Optional<TokenEndpointErrorResponse> parseErrorResponse(HttpStatusCodeException e) {
    try {
      TokenEndpointErrorResponse response =
          objectMapper.readValue(e.getResponseBodyAsByteArray(), TokenEndpointErrorResponse.class);

      return Optional.of(response);
    } catch (Exception jsonParsingError) {
      LOG.error("Error parsing token endpoint response: {}. input: {}",
          jsonParsingError.getMessage(), e.getResponseBodyAsString(), jsonParsingError);

      return Optional.empty();
    }

  }

  protected void prepareBasicAuthenticationHeader(HttpHeaders headers) {
    String auth = rcAuthProperties.getClientId() + ":" + rcAuthProperties.getClientSecret();
    byte[] encodedAuth = org.apache.commons.codec.binary.Base64
      .encodeBase64(auth.getBytes(StandardCharsets.US_ASCII));
    String authHeader = "Basic " + new String(encodedAuth);
    headers.set("Authorization", authHeader);
  }

  protected HttpEntity<MultiValueMap<String, String>> prepareTokenRequest(String code) {
    HttpHeaders headers = new HttpHeaders();

    prepareBasicAuthenticationHeader(headers);
    
    MultiValueMap<String, String> tokenRequestParams = new LinkedMultiValueMap<>();
    
    tokenRequestParams.add("grant_type", "authorization_code");
    tokenRequestParams.add("redirect_uri",
        String.format("%s%s", iamProperties.getBaseUrl(), CALLBACK_PATH));
    
    tokenRequestParams.add("client_id", rcAuthProperties.getClientId());
    tokenRequestParams.add("client_secret", rcAuthProperties.getClientSecret());
    tokenRequestParams.add("code", code);

    return new HttpEntity<>(tokenRequestParams, headers);
  }


  protected String resolveTokenEndpoint() {

    ServerConfiguration conf =
        serverConfigService.getServerConfiguration(rcAuthProperties.getIssuer());

    if (isNull(conf)) {
      throw new RCAuthError(
          "Configuration resolution failed for RCAuth issuer: " + rcAuthProperties.getIssuer());
    } else {
      return conf.getTokenEndpointUri();
    }
  }
  
  private void verifyTokenResponse(RCAuthTokenResponse response) {
    
    ServerConfiguration conf =
        serverConfigService.getServerConfiguration(rcAuthProperties.getIssuer());
    
    responseVerifier.verify(conf, response);
    
  }

  @Override
  public RCAuthTokenResponse getAccessToken(String code) {

    RestTemplate rt = restFactory.newRestTemplate();
    
    // ugly hack needed to workaround buggy oauth myproxy implementation
    // that does not set the content type for the token response
    rt.getInterceptors().add(new AddContentTypeInterceptor(APPLICATION_JSON_VALUE));

    try {

      RCAuthTokenResponse response = rt.postForObject(resolveTokenEndpoint(), prepareTokenRequest(code),
          RCAuthTokenResponse.class);
      
      verifyTokenResponse(response);
      
      return response;

    } catch (HttpStatusCodeException e) {

      LOG.debug(e.getMessage(), e);

      if (e.getStatusCode().equals(BAD_REQUEST)) {
        parseErrorResponse(e).ifPresent(er -> {

          String errorMessage = String.format("Token request error: %s '%s'", er.getError(),
              er.getErrorDescription());
          throw new RCAuthError(errorMessage, e);

        });
      }

      String errorMessage = String.format("Token request error: %s", e.getMessage());

      throw new RCAuthError(errorMessage, e);

    } catch (RestClientException e) {
      LOG.debug(e.getMessage(), e);
      throw new RCAuthError(e.getMessage(), e);
    }

  }
}
