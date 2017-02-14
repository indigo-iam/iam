package it.infn.mw.iam.core;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

public class IamOAuth2RequestFactory extends ConnectOAuth2RequestFactory {

  public static final String[] AUDIENCE_KEYS = {"aud", "audience"};
  public static final String AUD = "aud";


  public IamOAuth2RequestFactory(ClientDetailsEntityService clientDetailsService) {
    super(clientDetailsService);
  }

  /**
   * This implementation extends what's already done by MitreID implementation with audience request
   * parameter handling (both "aud" and "audience" are accepted).
   *
   *    
   */
  @Override
  public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest) {

    OAuth2Request request = super.createOAuth2Request(client, tokenRequest);

    for (String audienceKey : AUDIENCE_KEYS) {
      if (tokenRequest.getRequestParameters().containsKey(audienceKey)) {

        if (!request.getExtensions().containsKey(AUD)) {
          request.getExtensions().put(AUD, tokenRequest.getRequestParameters().get(audienceKey));
        }

        break;
      }
    }

    return request;
  }

}
