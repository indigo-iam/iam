package it.infn.mw.iam.api.tokens;

import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;

import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.api.tokens.service.filtering.TokensFilterRequest;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@Transactional
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/access-tokens")
public class AccessTokensController extends TokensControllerSupport {

  public static final Logger log = LoggerFactory.getLogger(AccessTokensController.class);

  @Autowired
  private TokenService<AccessToken> accessTokenService;

  @RequestMapping(method = RequestMethod.GET, produces = CONTENT_TYPE)
  public MappingJacksonValue listAccessTokens(
      @RequestParam(value = "count", required = false) Integer count,
      @RequestParam(value = "startIndex", required = false) Integer startIndex,
      @RequestParam(value = "userId", required = false) String userId,
      @RequestParam(value = "clientId", required = false) String clientId,
      @RequestParam(value = "attributes", required = false) final String attributes, 
      HttpServletRequest request) {

    TokensPageRequest pr = buildTokensPageRequest(count, startIndex);
    TokensFilterRequest fr = buildTokensFilterRequest(userId, clientId);
    return filterAttributes(accessTokenService.getList(pr, fr), attributes);
  }

  @RequestMapping(method = RequestMethod.GET, value = "/{id}", produces = CONTENT_TYPE)
  public AccessToken getAccessToken(@PathVariable("id") Long id,
      HttpServletRequest request, HttpServletResponse response) {

    log.debug("GET {}", request.getRequestURI());

    HttpStatus returnedStatus = null;
    AccessToken at = null;

    try {

      at = accessTokenService.getToken(id);
      log.debug("Access token: {}", at);
      returnedStatus = OK;

    } catch (TokenNotFoundException e) {

      log.debug("TokenNotFoundException: {}", e);
      returnedStatus = NOT_FOUND;
    }

    response.setStatus(returnedStatus.value());
    log.info("GET {} {}", request.getRequestURI(), returnedStatus);
    return at;
  }

  @RequestMapping(method = RequestMethod.DELETE, value = "/{id}")
  public void revokeAccessToken(@PathVariable("id") Long id, HttpServletRequest request,
      HttpServletResponse response) {

    log.debug("DELETE {}", request.getRequestURI());

    HttpStatus returnedStatus = null;

    try {

      accessTokenService.revokeToken(id);
      log.debug("Revoked access token with id: {}", id);
      returnedStatus = NO_CONTENT;

    } catch (TokenNotFoundException e) {

      log.debug("TokenNotFoundException: {}", e);
      returnedStatus = NOT_FOUND;
    }

    log.info("DELETE {} {}", request.getRequestURI(), returnedStatus);
    response.setStatus(returnedStatus.value());
  }
}
