package it.infn.mw.iam.api.authn_info;

import static it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler.EXT_AUTHN_UNREGISTERED_USER_ROLE;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;

@RestController
public class AuthnInfoController {

  public static final String BASE_RESOURCE = "/iam/authn-info";

  @RequestMapping(BASE_RESOURCE)
  @PreAuthorize("hasRole('" + EXT_AUTHN_UNREGISTERED_USER_ROLE + "')")
  public ExternalAuthenticationRegistrationInfo getAuthenticationInfo() {

    AbstractExternalAuthenticationToken<?> extAuthnToken =
	(AbstractExternalAuthenticationToken<?>) SecurityContextHolder.getContext()
	  .getAuthentication();

    return extAuthnToken.toExernalAuthenticationInfo();

  }
}
