package it.infn.mw.iam.core;

import java.util.HashSet;
import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;

@Service
@Primary
public class IamScopeClaimTranslationService implements ScopeClaimTranslationService {

  private SetMultimap<String, String> scopesToClaims = HashMultimap.create();

  public IamScopeClaimTranslationService() {
    // Mitreid scope mappings
    scopesToClaims.put("openid", "sub");

    scopesToClaims.put("profile", "name");
    scopesToClaims.put("profile", "preferred_username");
    scopesToClaims.put("profile", "given_name");
    scopesToClaims.put("profile", "family_name");
    scopesToClaims.put("profile", "middle_name");
    scopesToClaims.put("profile", "nickname");
    scopesToClaims.put("profile", "profile");
    scopesToClaims.put("profile", "picture");
    scopesToClaims.put("profile", "website");
    scopesToClaims.put("profile", "gender");
    scopesToClaims.put("profile", "zoneinfo");
    scopesToClaims.put("profile", "locale");
    scopesToClaims.put("profile", "updated_at");
    scopesToClaims.put("profile", "birthdate");

    scopesToClaims.put("email", "email");
    scopesToClaims.put("email", "email_verified");

    scopesToClaims.put("phone", "phone_number");
    scopesToClaims.put("phone", "phone_number_verified");

    scopesToClaims.put("address", "address");

    // Iam scope mappings
    scopesToClaims.put("profile", "organisation_name");
    scopesToClaims.put("profile", "groups");

  }

  @Override
  public Set<String> getClaimsForScope(String scope) {

    if (scopesToClaims.containsKey(scope)) {
      return scopesToClaims.get(scope);
    } else {
      return new HashSet<>();
    }
  }

  @Override
  public Set<String> getClaimsForScopeSet(Set<String> scopes) {

    Set<String> result = new HashSet<>();
    for (String scope : scopes) {
      result.addAll(getClaimsForScope(scope));
    }
    return result;

  }
}
