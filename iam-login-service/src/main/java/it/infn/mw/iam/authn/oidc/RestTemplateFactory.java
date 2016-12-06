package it.infn.mw.iam.authn.oidc;

import org.springframework.web.client.RestTemplate;

public interface RestTemplateFactory {

  RestTemplate newRestTemplate();

}
