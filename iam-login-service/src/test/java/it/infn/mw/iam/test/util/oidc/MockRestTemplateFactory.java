package it.infn.mw.iam.test.util.oidc;

import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;

public class MockRestTemplateFactory extends DefaultRestTemplateFactory {

  RestTemplate template;
  MockRestServiceServer mockServer;

  public MockRestTemplateFactory() {
    super(new HttpComponentsClientHttpRequestFactory());
    resetTemplate();
  }

  public MockRestServiceServer resetTemplate() {
    template = new RestTemplate();
    mockServer = MockRestServiceServer.createServer(template);
    return mockServer;
  }

  public MockRestServiceServer getMockServer() {
    return mockServer;
  }

  @Override
  public RestTemplate newRestTemplate() {
    return template;
  }


}
