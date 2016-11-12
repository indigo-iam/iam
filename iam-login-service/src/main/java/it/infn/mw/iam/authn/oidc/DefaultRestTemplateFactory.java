package it.infn.mw.iam.authn.oidc;

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class DefaultRestTemplateFactory implements RestTemplateFactory {

  private ClientHttpRequestFactory httpRequestFactory;

  public DefaultRestTemplateFactory(ClientHttpRequestFactory httpRequestFactory) {

    this.httpRequestFactory = httpRequestFactory;
  }

  @Override
  public RestTemplate newRestTemplate() {

    return new RestTemplate(httpRequestFactory);
  }

}
