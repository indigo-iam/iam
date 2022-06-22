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
package it.infn.mw.iam.core.userinfo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.HandlerInterceptor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;

@SuppressWarnings("deprecation")
public class IamUserInfoInterceptor implements HandlerInterceptor, AsyncHandlerInterceptor {

  public static final String USERINFO_ATTR_NAME = "userInfo";
  public static final String USERINFO_JSON_ATTR_NAME = "userInfoJson";

  private final Gson gsonBuilder;
  private final UserInfoService userInfoService;
  private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

  private static final JsonSerializer<GrantedAuthority> AUTHORITY_SERIALIZER =
      (src, type, context) -> new JsonPrimitive(src.getAuthority());

  @Autowired
  public IamUserInfoInterceptor(UserInfoService userInfoService) {
    this.userInfoService = userInfoService;
    gsonBuilder = new GsonBuilder()
      .registerTypeHierarchyAdapter(GrantedAuthority.class, AUTHORITY_SERIALIZER)
      .create();
  }

  private void resolveUserInfo(Authentication auth, HttpServletRequest request) {
    UserInfo user = userInfoService.getByUsername(auth.getName());

    if (user != null) {
      request.setAttribute(USERINFO_ATTR_NAME, user);
      request.setAttribute(USERINFO_JSON_ATTR_NAME, user.toJson());
    }
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth instanceof Authentication) {
      request.setAttribute("userAuthorities", gsonBuilder.toJson(auth.getAuthorities()));
    }

    if (!trustResolver.isAnonymous(auth)) {
      if (auth instanceof OAuth2Authentication) {

        OAuth2Authentication oauth = (OAuth2Authentication) auth;
        if (oauth.getUserAuthentication() != null) {
          resolveUserInfo(oauth.getUserAuthentication(), request);
        }
      } else if (auth != null && auth.getName() != null) {

        resolveUserInfo(auth, request);
      }
    }
    return true;
  }
}
