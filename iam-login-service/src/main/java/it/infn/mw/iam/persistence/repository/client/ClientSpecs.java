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
package it.infn.mw.iam.persistence.repository.client;



import static javax.persistence.criteria.JoinType.LEFT;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.data.jpa.domain.Specification;

import it.infn.mw.iam.api.client.search.ClientSearchForm;

public class ClientSpecs {
  static final String CLIENT_ID = "clientId";
  static final String CLIENT_NAME = "clientName";
  static final String DYNAMICALLY_REGISTERED = "dynamicallyRegistered";
  static final String CONTACTS = "contacts";
  static final String SCOPE = "scope";
  static final String GRANT_TYPES = "grantTypes";
  static final String REDIRECT_URIS = "redirectUris";
  static final String ACCOUNT = "account";
  static final String CLIENT = "account";
  static final String USERNAME = "username";

  public enum SearchType {
    name,
    contacts,
    scope,
    grantType,
    redirectUri
  }

  private ClientSpecs() {
    // do not instantiate
  }

  static String wildcardify(String filter) {
    return "%" + filter + "%";
  }

  public static Specification<ClientDetailsEntity> fromSearchForm(ClientSearchForm searchForm) {

    Specification<ClientDetailsEntity> spec;

    switch (searchForm.getSearchType()) {
      case contacts:
        spec = hasContactLike(searchForm.getSearch());
        break;
      case scope:
        spec = hasScopeLike(searchForm.getSearch());
        break;
      case grantType:
        spec = hasGrantTypeLike(searchForm.getSearch());
        break;
      case redirectUri:
        spec = hasRedirectUriLike(searchForm.getSearch());
        break;
      case name:
      default:
        spec =
            hasClientIdLike(searchForm.getSearch()).or(hasClientNameLike(searchForm.getSearch()));
    }

    if (searchForm.isDrOnly()) {
      spec = isDynamicallyRegistered().and(spec);
    }

    return spec;
  }


  public static Specification<ClientDetailsEntity> isDynamicallyRegistered() {
    return (root, query, builder) -> builder.isTrue(root.get(DYNAMICALLY_REGISTERED));
  }

  public static Specification<ClientDetailsEntity> hasClientIdLike(String filter) {
    return (root, query, builder) -> builder.like(root.get(CLIENT_ID), wildcardify(filter));
  }

  public static Specification<ClientDetailsEntity> hasClientNameLike(String filter) {
    return (root, query, builder) -> builder.like(root.get(CLIENT_NAME), wildcardify(filter));
  }

  public static Specification<ClientDetailsEntity> hasContactLike(String filter) {
    return (root, query, builder) -> {
      query.distinct(true);
      return builder.like(builder.lower(root.joinSet(CONTACTS, LEFT)),
          wildcardify(filter.toLowerCase()));
    };
  }

  public static Specification<ClientDetailsEntity> hasGrantTypeLike(String grantType) {
    return (root, query, builder) -> {
      query.distinct(true);
      return builder.like(root.joinSet(GRANT_TYPES), wildcardify(grantType));
    };
  }

  public static Specification<ClientDetailsEntity> hasScopeLike(String scope) {
    return (root, query, builder) -> {
      query.distinct(true);   
      return builder.like(root.joinSet(SCOPE), wildcardify(scope));
    };
  }

  public static Specification<ClientDetailsEntity> hasRedirectUriLike(String redirectUri) {
    return (root, query, builder) -> {
      query.distinct(true);
      return builder.like(root.joinSet(REDIRECT_URIS), wildcardify(redirectUri));
    };
  }
}
