package it.infn.mw.tc;

import static org.mitre.util.JsonUtils.getAsBoolean;
import static org.mitre.util.JsonUtils.getAsEncryptionMethodList;
import static org.mitre.util.JsonUtils.getAsJweAlgorithmList;
import static org.mitre.util.JsonUtils.getAsJwsAlgorithmList;
import static org.mitre.util.JsonUtils.getAsString;
import static org.mitre.util.JsonUtils.getAsStringList;

import java.util.concurrent.ExecutionException;

import org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class IamDynamicServerConfigurationService extends DynamicServerConfigurationService {

  private static final Logger logger =
      LoggerFactory.getLogger(IamDynamicServerConfigurationService.class);

  private LoadingCache<String, ServerConfiguration> servers;

  public IamDynamicServerConfigurationService(ClientHttpRequestFactory requestFactory) {

    servers = CacheBuilder.newBuilder().build(new Fetcher(requestFactory));

  }

  @Override
  public ServerConfiguration getServerConfiguration(String issuer) {
    try {

      if (!getWhitelist().isEmpty() && !getWhitelist().contains(issuer)) {
        throw new AuthenticationServiceException(
            "Whitelist was nonempty, issuer was not in whitelist: " + issuer);
      }

      if (getBlacklist().contains(issuer)) {
        throw new AuthenticationServiceException("Issuer was in blacklist: " + issuer);
      }

      return servers.get(issuer);
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.warn("Couldn't load configuration for " + issuer + ": " + e);
      return null;
    }

  }

  private static class Fetcher extends CacheLoader<String, ServerConfiguration> {

    private static final Logger logger = LoggerFactory.getLogger(Fetcher.class);

    private ClientHttpRequestFactory factory;

    public Fetcher(ClientHttpRequestFactory factory) {
      this.factory = factory;
    }

    @Override
    public ServerConfiguration load(String issuer) throws Exception {

      RestTemplate restTemplate = new RestTemplate(factory);

      // data holder
      ServerConfiguration conf = new ServerConfiguration();

      // construct the well-known URI
      String url = issuer + "/.well-known/openid-configuration";

      // fetch the value
      String jsonString = restTemplate.getForObject(url, String.class);

      JsonElement parsed = JsonParser.parseString(jsonString);

      if (parsed.isJsonObject()) {

        JsonObject o = parsed.getAsJsonObject();

        // sanity checks
        if (!o.has("issuer")) {
          throw new IllegalStateException("Returned object did not have an 'issuer' field");
        }

        if (!issuer.equals(o.get("issuer").getAsString())) {
          logger.info("Issuer used for discover was {} but the final issuer is {}", issuer,  
              o.get("issuer").getAsString());
        }

        conf.setIssuer(o.get("issuer").getAsString());

        conf.setAuthorizationEndpointUri(getAsString(o, "authorization_endpoint"));
        conf.setTokenEndpointUri(getAsString(o, "token_endpoint"));
        conf.setJwksUri(getAsString(o, "jwks_uri"));
        conf.setUserInfoUri(getAsString(o, "userinfo_endpoint"));
        conf.setRegistrationEndpointUri(getAsString(o, "registration_endpoint"));
        conf.setIntrospectionEndpointUri(getAsString(o, "introspection_endpoint"));
        conf.setAcrValuesSupported(getAsStringList(o, "acr_values_supported"));
        conf.setCheckSessionIframe(getAsString(o, "check_session_iframe"));
        conf.setClaimsLocalesSupported(getAsStringList(o, "claims_locales_supported"));
        conf.setClaimsParameterSupported(getAsBoolean(o, "claims_parameter_supported"));
        conf.setClaimsSupported(getAsStringList(o, "claims_supported"));
        conf.setDisplayValuesSupported(getAsStringList(o, "display_values_supported"));
        conf.setEndSessionEndpoint(getAsString(o, "end_session_endpoint"));
        conf.setGrantTypesSupported(getAsStringList(o, "grant_types_supported"));
        conf.setIdTokenSigningAlgValuesSupported(
            getAsJwsAlgorithmList(o, "id_token_signing_alg_values_supported"));
        conf.setIdTokenEncryptionAlgValuesSupported(
            getAsJweAlgorithmList(o, "id_token_encryption_alg_values_supported"));
        conf.setIdTokenEncryptionEncValuesSupported(
            getAsEncryptionMethodList(o, "id_token_encryption_enc_values_supported"));
        conf.setOpPolicyUri(getAsString(o, "op_policy_uri"));
        conf.setOpTosUri(getAsString(o, "op_tos_uri"));
        conf.setRequestObjectEncryptionAlgValuesSupported(
            getAsJweAlgorithmList(o, "request_object_encryption_alg_values_supported"));
        conf.setRequestObjectEncryptionEncValuesSupported(
            getAsEncryptionMethodList(o, "request_object_encryption_enc_values_supported"));
        conf.setRequestObjectSigningAlgValuesSupported(
            getAsJwsAlgorithmList(o, "request_object_signing_alg_values_supported"));
        conf.setRequestParameterSupported(getAsBoolean(o, "request_parameter_supported"));
        conf.setRequestUriParameterSupported(getAsBoolean(o, "request_uri_parameter_supported"));
        conf.setResponseTypesSupported(getAsStringList(o, "response_types_supported"));
        conf.setScopesSupported(getAsStringList(o, "scopes_supported"));
        conf.setSubjectTypesSupported(getAsStringList(o, "subject_types_supported"));
        conf.setServiceDocumentation(getAsString(o, "service_documentation"));
        conf.setTokenEndpointAuthMethodsSupported(
            getAsStringList(o, "token_endpoint_auth_methods"));
        conf.setTokenEndpointAuthSigningAlgValuesSupported(
            getAsJwsAlgorithmList(o, "token_endpoint_auth_signing_alg_values_supported"));
        conf.setUiLocalesSupported(getAsStringList(o, "ui_locales_supported"));
        conf.setUserinfoEncryptionAlgValuesSupported(
            getAsJweAlgorithmList(o, "userinfo_encryption_alg_values_supported"));
        conf.setUserinfoEncryptionEncValuesSupported(
            getAsEncryptionMethodList(o, "userinfo_encryption_enc_values_supported"));
        conf.setUserinfoSigningAlgValuesSupported(
            getAsJwsAlgorithmList(o, "userinfo_signing_alg_values_supported"));

        return conf;
      } else {
        throw new IllegalStateException("Couldn't parse server discovery results for " + url);
      }

    }

  }
}
