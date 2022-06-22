package it.infn.mw.tc;

import java.io.IOException;
import java.security.Principal;
import java.text.ParseException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import com.nimbusds.jwt.JWTParser;

@SpringBootApplication
@EnableAutoConfiguration(exclude = {ErrorMvcAutoConfiguration.class})
@RestController
public class IamTestClientApplication extends WebSecurityConfigurerAdapter {

  public static final Logger LOG = LoggerFactory.getLogger(IamTestClientApplication.class);

  @Autowired
  OIDCAuthenticationFilter oidcFilter;

  @Autowired
  IamClientApplicationProperties properties;

  @Autowired
  ClientHttpRequestFactory requestFactory;

  public static void main(String[] args) {

    SpringApplication.run(IamTestClientApplication.class, args);
  }

  public class SendUnauhtorizedAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) throws IOException, ServletException {

      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

    }

  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // @formatter:off
    http.antMatcher("/**").authorizeRequests()
        .antMatchers("/", "/user", "/error", "/openid_connect_login**", "/webjars/**").permitAll()
        .anyRequest().authenticated().and().exceptionHandling()
        .authenticationEntryPoint(new SendUnauhtorizedAuthenticationEntryPoint()).and().logout()
        .logoutSuccessUrl("/").permitAll().and().csrf().csrfTokenRepository(csrfTokenRepository())
        .and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
        .addFilterAfter(oidcFilter, SecurityContextPersistenceFilter.class).sessionManagement()
        .enableSessionUrlRewriting(false).sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
    // @formatter:on
  }

  private Filter csrfHeaderFilter() {

    return new OncePerRequestFilter() {

      @Override
      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
          FilterChain filterChain) throws ServletException, IOException {

        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrf != null) {
          Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
          String token = csrf.getToken();
          if (cookie == null || token != null && !token.equals(cookie.getValue())) {
            cookie = new Cookie("XSRF-TOKEN", token);
            cookie.setPath("/");
            response.addCookie(cookie);
          }
        }
        filterChain.doFilter(request, response);
      }
    };
  }

  private CsrfTokenRepository csrfTokenRepository() {

    HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
    repository.setHeaderName("X-XSRF-TOKEN");
    return repository;
  }

  @RequestMapping("/user")
  public OpenIDAuthentication info(Principal principal) {

    if (principal instanceof AnonymousAuthenticationToken) {
      return null;
    }

    if (principal instanceof OIDCAuthenticationToken) {
      OIDCAuthenticationToken token = (OIDCAuthenticationToken) principal;
      OpenIDAuthentication auth = new OpenIDAuthentication();

      auth.setIssuer(token.getIssuer());
      auth.setSub(token.getSub());

      if (!properties.isHideTokens()) {
        auth.setAccessToken(token.getAccessTokenValue());
        auth.setIdToken(token.getIdToken().getParsedString());
        auth.setRefreshToken(token.getRefreshTokenValue());
      }

      try {
        auth.setAccessTokenClaims(JWTParser.parse(token.getAccessTokenValue())
          .getJWTClaimsSet()
          .toString());

        auth.setIdTokenClaims(token.getIdToken().getJWTClaimsSet().toString());
      } catch (ParseException e) {
        LOG.error(e.getMessage(), e);
      }

      auth.setName(token.getUserInfo().getName());
      auth.setFamilyName(token.getUserInfo().getFamilyName());
      auth.setUserInfo(token.getUserInfo().toJson().toString());

      return auth;
    }

    return null;
  }

  @RequestMapping("/introspect")
  public String introspect(Principal principal, Model model) {

    if (principal instanceof AnonymousAuthenticationToken) {
      return null;
    }


    if (principal == null || principal instanceof AnonymousAuthenticationToken) {
      model.addAttribute("error", "User is not authenticated.");
      return "index";
    }

    OIDCAuthenticationToken token = (OIDCAuthenticationToken) principal;
    String accessToken = token.getAccessTokenValue();

    String plainCreds =
        String.format("%s:%s", properties.getClient().getClientId(),
            properties.getClient().getClientSecret());

    String base64Creds = new String(java.util.Base64.getEncoder().encode(plainCreds.getBytes()));

    HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Basic " + base64Creds);

    // Create the request body as a MultiValueMap
    MultiValueMap<String, String> body = new LinkedMultiValueMap<String, String>();
    body.add("token", accessToken);

    HttpEntity<?> request = new HttpEntity<>(body, headers);

    RestTemplate rt = new RestTemplate(requestFactory);
    String iamIntrospectUrl = properties.getIssuer() + "/introspect";
    ResponseEntity<String> response =
        rt.exchange(iamIntrospectUrl, HttpMethod.POST, request, String.class);

    if (response.getStatusCode().is4xxClientError()
        || response.getStatusCode().is5xxServerError()) {
      model.addAttribute("error", "Introspect call returned an error: " + response.getBody());
      return null;
    }

    return response.getBody();
  }

}
