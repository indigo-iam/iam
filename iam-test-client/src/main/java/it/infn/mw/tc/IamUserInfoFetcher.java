package it.infn.mw.tc;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mitre.openid.connect.config.ServerConfiguration.UserInfoTokenMethod;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class IamUserInfoFetcher extends UserInfoFetcher {

  private static final Logger logger = LoggerFactory.getLogger(IamUserInfoFetcher.class);

  private LoadingCache<PendingOIDCAuthenticationToken, UserInfo> cache;
  private ClientHttpRequestFactory requestFactory;

  public IamUserInfoFetcher(ClientHttpRequestFactory rf) {
    requestFactory = rf;
    cache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS) // expires
                                                                          // 1
                                                                          // hour
                                                                          // after
                                                                          // fetch
        .maximumSize(100).build(new Loader());
  }

  @Override
  public UserInfo loadUserInfo(PendingOIDCAuthenticationToken token) {

    try {
      return cache.get(token);
    } catch (ExecutionException e) {
      logger.debug(e.getMessage());
      return null;
    }

  }

  private class Loader extends CacheLoader<PendingOIDCAuthenticationToken, UserInfo> {

    @Override
    public UserInfo load(PendingOIDCAuthenticationToken token) throws Exception {

      ServerConfiguration serverConfiguration = token.getServerConfiguration();

      if (serverConfiguration == null) {
        logger.warn("No server configuration found.");
        return null;
      }

      if (Strings.isNullOrEmpty(serverConfiguration.getUserInfoUri())) {
        logger.warn("No userinfo endpoint, not fetching.");
        return null;
      }

      try {

        String userInfoString = null;

        if (serverConfiguration.getUserInfoTokenMethod() == null
            || serverConfiguration.getUserInfoTokenMethod().equals(UserInfoTokenMethod.HEADER)) {
          RestTemplate restTemplate = new RestTemplate(requestFactory) {

            @Override
            protected ClientHttpRequest createRequest(URI url, HttpMethod method)
                throws IOException {

              ClientHttpRequest httpRequest = super.createRequest(url, method);
              httpRequest.getHeaders().add("Authorization",
                  String.format("Bearer %s", token.getAccessTokenValue()));
              return httpRequest;
            }
          };

          userInfoString =
              restTemplate.getForObject(serverConfiguration.getUserInfoUri(), String.class);

        } else if (serverConfiguration.getUserInfoTokenMethod().equals(UserInfoTokenMethod.FORM)) {
          MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
          form.add("access_token", token.getAccessTokenValue());

          RestTemplate restTemplate = new RestTemplate(requestFactory);
          userInfoString =
              restTemplate.postForObject(serverConfiguration.getUserInfoUri(), form, String.class);
        } else if (serverConfiguration.getUserInfoTokenMethod().equals(UserInfoTokenMethod.QUERY)) {
          URIBuilder builder = new URIBuilder(serverConfiguration.getUserInfoUri());
          builder.setParameter("access_token", token.getAccessTokenValue());

          RestTemplate restTemplate = new RestTemplate(requestFactory);
          userInfoString = restTemplate.getForObject(builder.toString(), String.class);
        }

        if (!Strings.isNullOrEmpty(userInfoString)) {

          JsonObject userInfoJson = JsonParser.parseString(userInfoString).getAsJsonObject();

          UserInfo userInfo = fromJson(userInfoJson);

          return userInfo;
        } else {
          // didn't get anything, return null
          return null;
        }
      } catch (Exception e) {
        logger.warn("Error fetching userinfo", e);
        return null;
      }

    }

  }

}
