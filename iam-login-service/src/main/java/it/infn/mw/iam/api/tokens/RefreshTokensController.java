package it.infn.mw.iam.api.tokens;

import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;

import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
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
@RequestMapping("/refresh-tokens")
@PreAuthorize("hasRole('ADMIN')")
public class RefreshTokensController extends TokensControllerSupport {

  public static final Logger log = LoggerFactory.getLogger(RefreshTokensController.class);

  public static final String CONTENT_TYPE = "application/json";

  @Autowired
  private TokenService<RefreshToken> refreshTokenService;

  @RequestMapping(method = RequestMethod.GET, produces = CONTENT_TYPE)
  public MappingJacksonValue lisRefreshTokens(
      @RequestParam(value = "count", required = false) Integer count,
      @RequestParam(value = "startIndex", required = false) Integer startIndex,
      @RequestParam(value = "userId", required = false) String userId,
      @RequestParam(value = "clientId", required = false) String clientId,
      @RequestParam(value = "attributes", required = false) final String attributes,
      HttpServletRequest request) {

    TokensPageRequest pr = buildTokensPageRequest(count, startIndex);
    TokensFilterRequest fr = buildTokensFilterRequest(userId, clientId);
    return filterAttributes(refreshTokenService.getList(pr, fr), attributes);
  }

  @RequestMapping(method = RequestMethod.GET, value = "/{id}", produces = CONTENT_TYPE)
  public RefreshToken getRefreshToken(@PathVariable("id") Long id, HttpServletRequest request,
      HttpServletResponse response) {

    log.debug("GET {}", request.getRequestURI());

    HttpStatus returnedStatus = null;
    RefreshToken rt = null;

    try {

      rt = refreshTokenService.getToken(id);
      log.debug("Refresh token: {}", rt);
      returnedStatus = OK;

    } catch (TokenNotFoundException e) {

      log.debug("TokenNotFoundException: {}", e);
      returnedStatus = NOT_FOUND;
    }

    response.setStatus(returnedStatus.value());
    log.info("GET {} {}", request.getRequestURI(), returnedStatus);
    return rt;
  }

  @RequestMapping(method = RequestMethod.DELETE, value = "/{id}")
  public void revokeRefreshToken(@PathVariable("id") Long id, HttpServletRequest request,
      HttpServletResponse response) {

    log.debug("DELETE {}", request.getRequestURI());

    HttpStatus returnedStatus = null;

    try {

      refreshTokenService.revokeToken(id);
      log.debug("Revoked refresh token with id: {}", id);
      returnedStatus = NO_CONTENT;

    } catch (TokenNotFoundException e) {

      log.debug("TokenNotFoundException: {}", e);
      returnedStatus = NOT_FOUND;
    }

    response.setStatus(returnedStatus.value());
    log.info("DELETE {} {}", request.getRequestURI(), NOT_FOUND);
    return;
  }
}
