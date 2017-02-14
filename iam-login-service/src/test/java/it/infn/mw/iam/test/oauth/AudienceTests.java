package it.infn.mw.iam.test.oauth;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.text.ParseException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class AudienceTests {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";


  @Value("${server.port}")
  private Integer iamPort;

  @Test
  public void testAudienceRequestPasswordFlow() throws ParseException {

    String accessToken = passwordTokenGetter().username(TEST_USERNAME)
      .password(TEST_PASSWORD)
      .audience("example-audience")
      .getAccessToken();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("example-audience"));
  }

  @Test
  public void testAudienceRequestClientCredentialsFlow() throws ParseException {

    String accessToken =
        TestUtils.clientCredentialsTokenGetter().audience("example-audience").getAccessToken();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("example-audience"));
  }

}
