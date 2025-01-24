package it.infn.mw.iam.api.client.management.service;

import java.util.Date;

import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamClient;

@SuppressWarnings("deprecation")
public interface OIDCTokenService {

  public JWT createIdToken(IamClient client, OAuth2Request request, Date issueTime,
      String sub, IamAccessToken accessToken);

  public IamAccessToken createRegistrationAccessToken(IamClient client);

  public IamAccessToken createResourceAccessToken(IamClient client);

  public IamAccessToken rotateRegistrationAccessTokenForClient(IamClient client);
}
