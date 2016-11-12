package it.infn.mw.iam.core;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.impl.DefaultIntrospectionResultAssembler;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;

import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

public class IamIntrospectionResultAssembler extends DefaultIntrospectionResultAssembler {
  private static final Logger LOGGER =
      LoggerFactory.getLogger(IamIntrospectionResultAssembler.class);

  public static final String PREFERRED_USERNAME = "preferred_username";
  public static final String EMAIL = "email";
  public static final String GROUPS = "groups";
  public static final String ORGANISATION_NAME = "organisation_name";

  public IamIntrospectionResultAssembler() {}

  @Override
  public Map<String, Object> assembleFrom(OAuth2AccessTokenEntity accessToken, UserInfo userInfo,
      Set<String> authScopes) {

    Map<String, Object> result = super.assembleFrom(accessToken, userInfo, authScopes);

    try {

      List<String> audience = accessToken.getJwt().getJWTClaimsSet().getAudience();

      if (audience != null && audience.size() > 0) {
        result.put("aud", Joiner.on(' ').join(audience));
      }

    } catch (ParseException e) {
      LOGGER.error("Error getting audience out of access token: {}", e.getMessage(), e);
    }

    // Intersection of scopes authorised for the client and scopes linked to the
    // access token
    Set<String> scopes = Sets.intersection(authScopes, accessToken.getScope());

    if (userInfo != null) {
      if (scopes.contains("profile")) {

        IamUserInfo iamUserInfo = (IamUserInfo) userInfo;

        if (!iamUserInfo.getGroups().isEmpty()) {

          result.put(GROUPS,
              iamUserInfo.getGroups().stream().map(IamGroup::getName).collect(Collectors.toList()));
        }

        result.put(PREFERRED_USERNAME, iamUserInfo.getPreferredUsername());

        result.put(ORGANISATION_NAME, IamProperties.INSTANCE.getOrganisationName());
      }

      if (scopes.contains("email")) {
        result.put(EMAIL, userInfo.getEmail());
      }
    }

    return result;
  }

}
