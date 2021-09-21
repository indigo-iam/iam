package it.infn.mw.tc;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.google.common.base.Joiner;
import com.google.common.base.Strings;

public class IamAuthRequestUrlBuilder implements AuthRequestUrlBuilder {


  @Override
  public String buildAuthRequestUrl(ServerConfiguration serverConfig, RegisteredClient clientConfig,
      String redirectUri, String nonce, String state, Map<String, String> options,
      String loginHint) {

    try {

      URIBuilder uriBuilder = new URIBuilder(serverConfig.getAuthorizationEndpointUri());
      uriBuilder.addParameter("response_type", "code");
      uriBuilder.addParameter("client_id", clientConfig.getClientId());

      if (options.get("scope") != null) {
        uriBuilder.addParameter("scope", options.get("scope"));
      } else {
        uriBuilder.addParameter("scope", Joiner.on(" ").join(clientConfig.getScope()));
      }


      uriBuilder.addParameter("redirect_uri", redirectUri);

      uriBuilder.addParameter("nonce", nonce);

      uriBuilder.addParameter("state", state);

      // Optional parameters:
      for (Entry<String, String> option : options.entrySet()) {
        uriBuilder.addParameter(option.getKey(), option.getValue());
      }

      // if there's a login hint, send it
      if (!Strings.isNullOrEmpty(loginHint)) {
        uriBuilder.addParameter("login_hint", loginHint);
      }

      return uriBuilder.build().toString();

    } catch (URISyntaxException e) {
      throw new AuthenticationServiceException("Malformed Authorization Endpoint Uri", e);

    }

  }

}
