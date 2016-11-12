package it.infn.mw.iam.authn.oidc;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.apache.commons.lang.NotImplementedException;
import org.mitre.oauth2.model.RegisteredClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.authn.oidc.OidcClientFilter.OidcProviderConfiguration;
import it.infn.mw.iam.authn.oidc.model.TokenEndpointErrorResponse;

public class DefaultOidcTokenRequestor implements OidcTokenRequestor {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultOidcTokenRequestor.class);

  public static final String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";

  final RestTemplateFactory restTemplateFactory;
  final ObjectMapper jacksonObjectMapper;

  @Autowired
  public DefaultOidcTokenRequestor(RestTemplateFactory restTemplateFactory, ObjectMapper mapper) {
    this.restTemplateFactory = restTemplateFactory;
    this.jacksonObjectMapper = mapper;
  }

  private void basicAuthRequest(RegisteredClient clientConfig, HttpHeaders headers) {

    String auth = clientConfig.getClientId() + ":" + clientConfig.getClientSecret();
    byte[] encodedAuth = org.apache.commons.codec.binary.Base64
      .encodeBase64(auth.getBytes(StandardCharsets.US_ASCII));
    String authHeader = "Basic " + new String(encodedAuth);

    headers.set("Authorization", authHeader);
  }

  private void jwtAuthRequest(RegisteredClient clientConfig) {

    throw new NotImplementedException("Signed JWT authN method not yet implemented");
  }

  private void jwtPrivateKeyAuthRequest(RegisteredClient clientConfig) {

    throw new NotImplementedException("JWT authN method not yet implemented");
  }

  protected void formAuthRequest(RegisteredClient clientConfig,
      MultiValueMap<String, String> requestParams) {

    requestParams.add("client_id", clientConfig.getClientId());
    requestParams.add("client_secret", clientConfig.getClientSecret());

  }

  protected HttpEntity<MultiValueMap<String, String>> prepareTokenRequest(
      OidcProviderConfiguration config, MultiValueMap<String, String> tokenRequestParams) {

    HttpHeaders headers = new HttpHeaders();

    switch (config.clientConfig.getTokenEndpointAuthMethod()) {

      case SECRET_BASIC:
	basicAuthRequest(config.clientConfig, headers);
	break;
      case SECRET_JWT:
	jwtAuthRequest(config.clientConfig);
	break;
      case PRIVATE_KEY:
	jwtPrivateKeyAuthRequest(config.clientConfig);
	break;
      case SECRET_POST:
	formAuthRequest(config.clientConfig, tokenRequestParams);
	break;
      case NONE:
	break;

      default:
	throw new AuthenticationServiceException(
	    "Unsupported token endpoint authentication method");
    }

    HttpEntity<MultiValueMap<String, String>> tokenRequest =
	new HttpEntity<>(tokenRequestParams, headers);

    return tokenRequest;
  }

  Optional<TokenEndpointErrorResponse> parseErrorResponse(HttpClientErrorException e) {
    try {
      TokenEndpointErrorResponse response = jacksonObjectMapper
	.readValue(e.getResponseBodyAsByteArray(), TokenEndpointErrorResponse.class);

      return Optional.of(response);
    } catch (Exception jsonParsingError) {
      LOG.error("Error parsing token endpoint response: {}. input: {}",
	  jsonParsingError.getMessage(), e.getResponseBodyAsString());

      return Optional.empty();
    }

  }

  @Override
  public String requestTokens(OidcProviderConfiguration conf,
      MultiValueMap<String, String> tokenRequestParams) {

    RestOperations restTemplate = restTemplateFactory.newRestTemplate();

    try {

      return restTemplate.postForObject(conf.serverConfig.getTokenEndpointUri(),
	  prepareTokenRequest(conf, tokenRequestParams), String.class);

    } catch (HttpClientErrorException e) {

      if (e.getStatusCode() != null && e.getStatusCode().equals(BAD_REQUEST)) {
	parseErrorResponse(e).ifPresent(er -> {


	  String errorMessage = String.format("Token request error: %s '%s'", er.getError(),
	      er.getErrorDescription());
	  LOG.error(errorMessage);

	  throw new OidcClientError(e.getMessage(), er.getError(), er.getErrorDescription(),
	      er.getErrorUri());

	});
      }

      String errorMessage = String.format("Token request error: %s", e.getMessage());
      LOG.error(errorMessage, e);
      throw new OidcClientError(errorMessage, e);
    } catch (Throwable e) {
      String errorMessage = String.format("Token request error: %s", e.getMessage());
      LOG.error(errorMessage, e);
      throw new OidcClientError(errorMessage, e);
    }

  }

}
