package it.infn.mw.iam.test.dashboard;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.PKCEAlgorithm;

import java.text.ParseException;
import java.util.Set;
import com.google.common.collect.Sets;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;

@ExtendWith(MockitoExtension.class)
public class DashboardConfigServiceTest {

  private static final String CLIENT_ID = "dashboard-client";
  private static final String CLIENT_SECRET = "secret";
  private static final String BASE_URL = "http://localhost:8080";
  private static final Set<String> SCOPES = Sets.newHashSet("openid", "profile", "email", "iam:admin.read",
      "iam:admin.write", "scim:read", "scim:write", "offline_access");
  private static final Set<String> AUTH_GRAND_TYPE = Set.of(AuthorizationGrantType.CODE.getGrantType(),
      AuthorizationGrantType.REFRESH_TOKEN.getGrantType());

  private ClientDetailsEntity client;

  @InjectMocks
  private DashboardConfigService dashboardConfigService;

  @Mock
  private IamClientRepository iamClientDetailsRepository;

  @Mock
  private DefaultClientManagementService clientService;

  @BeforeEach
  void setUp() {
    this.client = new ClientDetailsEntity();
    client.setClientId(CLIENT_ID);
    client.setClientSecret(CLIENT_SECRET);
    client.setScope(SCOPES);
    client.setGrantTypes(AUTH_GRAND_TYPE);
    client.setRedirectUris(Set.of("http://localhost:8080/api/auth/oauth2/callback/indigo-iam"));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    iamClientDetailsRepository.save(client);
  }

  @AfterEach
  void tearDown() {
    iamClientDetailsRepository.delete(client);
  }

  @Test
  void testCheckRecordConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES);

    assertEquals(dashboardConfigService.checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL), true);
  }

  @Test
  void testFailCheckRecordScopeConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE,
        Sets.newHashSet("openid"));

    assertEquals(dashboardConfigService.checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL), false);
  }

  @Test
  void testFailCheckRecordClientSecretConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES);

    assertEquals(dashboardConfigService.checkRecordConfiguration(client, "test_secret", BASE_URL), false);
  }

  @Test
  void testInitDashboardClient() throws ParseException {
    DashboardProperties properties = new DashboardProperties();
    properties.setClientId(CLIENT_ID);
    properties.setClientSecret(CLIENT_SECRET);

    assertEquals(dashboardConfigService.initDashboardClient(properties, BASE_URL), true);
  }

  private ClientDetailsEntity createClientDashboard(String clientId, String clientSecret,
      String redirectUris, Set<String> grantTypes, Set<String> scopes) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(clientId);
    client.setClientSecret(clientSecret);
    client.setScope(scopes);
    client.setGrantTypes(grantTypes);
    client.setRedirectUris(Set.of(redirectUris));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    return client;
  }
}
