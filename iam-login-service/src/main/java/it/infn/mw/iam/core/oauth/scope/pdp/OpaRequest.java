package it.infn.mw.iam.core.oauth.scope.pdp;

import java.util.Set;

public record OpaRequest(User user, Set<String> scopes) {
  public record User(String id, Set<String> groups) {}

}
