package it.infn.mw.tc;

import static java.util.stream.Collectors.toSet;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.client.HttpClient;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.logging.log4j.util.Strings;
import org.italiangrid.voms.util.CertificateValidatorBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;

@Configuration
public class IamTestClientConfiguration {

  @Autowired
  private IamClientApplicationProperties iamClientConfig;

  @Bean
  public FilterRegistrationBean<OIDCAuthenticationFilter> disabledAutomaticOidcFilterRegistration(
      OIDCAuthenticationFilter f) {
    FilterRegistrationBean<OIDCAuthenticationFilter> b =
        new FilterRegistrationBean<OIDCAuthenticationFilter>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean(name = "openIdConnectAuthenticationFilter")
  public OIDCAuthenticationFilter openIdConnectAuthenticationFilter()
      throws NoSuchAlgorithmException, KeyStoreException {

    ClientHttpRequestFactory rf = httpRequestFactory();
    IamOIDCClientFilter filter = new IamOIDCClientFilter();

    filter.setAuthenticationManager(authenticationManager());
    filter.setIssuerService(iamIssuerService());

    filter.setServerConfigurationService(new IamDynamicServerConfigurationService(rf));
    filter.setValidationServices(new IamJWKCacheSetService(rf));

    filter.setClientConfigurationService(staticClientConfiguration());
    filter.setAuthRequestOptionsService(authOptions());
    filter.setAuthRequestUrlBuilder(new IamAuthRequestUrlBuilder());
    filter.setHttpRequestFactory(httpRequestFactory());



    filter.setAuthenticationFailureHandler(new SaveAuhenticationError());


    return filter;
  }

  @Bean(name = "OIDCAuthenticationManager")
  public AuthenticationManager authenticationManager()
      throws NoSuchAlgorithmException, KeyStoreException {

    return new ProviderManager(Arrays.asList(openIdConnectAuthenticationProvider()));
  }

  @Bean
  public OIDCAuthenticationProvider openIdConnectAuthenticationProvider()
      throws NoSuchAlgorithmException {

    OIDCAuthenticationProvider provider = new OIDCAuthenticationProvider();
    provider.setUserInfoFetcher(new IamUserInfoFetcher(httpRequestFactory()));

    return provider;
  }

  private IssuerService iamIssuerService() {

    StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
    issuerService.setIssuer(iamClientConfig.getIssuer());

    return issuerService;
  }

  private StaticClientConfigurationService staticClientConfiguration() {

    Map<String, RegisteredClient> clients = new LinkedHashMap<>();

    ClientDetailsEntity cde = new ClientDetailsEntity();
    cde.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    cde.setClientId(iamClientConfig.getClient().getClientId());
    cde.setClientSecret(iamClientConfig.getClient().getClientSecret());

    if (Strings.isNotBlank(iamClientConfig.getClient().getScope())) {
      cde.setScope(
          Stream.of(iamClientConfig.getClient().getScope().split(" ")).collect(toSet()));
    }

    clients.put(iamClientConfig.getIssuer(), new RegisteredClient(cde));

    StaticClientConfigurationService config = new StaticClientConfigurationService();
    config.setClients(clients);

    return config;
  }

  private AuthRequestOptionsService authOptions() {

    return new IamAuthRequestOptionsService(iamClientConfig);
  }

  public X509CertChainValidatorExt certificateValidator() {
    NamespaceCheckingMode namespaceChecks = CertificateValidatorBuilder.DEFAULT_NS_CHECKS;

    if (iamClientConfig.getTls().isIgnoreNamespaceChecks()) {
      namespaceChecks = NamespaceCheckingMode.IGNORE;
    }

    return new CertificateValidatorBuilder().lazyAnchorsLoading(false)
      .namespaceChecks(namespaceChecks)
      .trustAnchorsUpdateInterval(TimeUnit.HOURS.toMillis(1))
      .build();
  }


  public SSLContext sslContext() throws NoSuchAlgorithmException {

    SecureRandom r = new SecureRandom();

    try {
      SSLContext context = SSLContext.getInstance(iamClientConfig.getTls().getVersion());

      X509TrustManager tm = SocketFactoryCreator.getSSLTrustManager(certificateValidator());
      context.init(null, new TrustManager[] {tm}, r);

      return context;

    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new RuntimeException(e);
    }

  }

  public HttpClient httpClient() throws NoSuchAlgorithmException {

    SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(sslContext());

    Registry<ConnectionSocketFactory> socketFactoryRegistry =
        RegistryBuilder.<ConnectionSocketFactory>create()
          .register("https", sf)
          .register("http", PlainConnectionSocketFactory.getSocketFactory())
          .build();

    PoolingHttpClientConnectionManager connectionManager =
        new PoolingHttpClientConnectionManager(socketFactoryRegistry);
    connectionManager.setMaxTotal(10);
    connectionManager.setDefaultMaxPerRoute(10);

    return HttpClientBuilder.create()
      .setConnectionManager(connectionManager)
      .disableAuthCaching()
      .build();
  }

  @Bean
  public ClientHttpRequestFactory httpRequestFactory() throws NoSuchAlgorithmException {

    if (iamClientConfig.getTls().isUseGridTrustAnchors()) {
      return new HttpComponentsClientHttpRequestFactory(httpClient());
    } else {
      return new HttpComponentsClientHttpRequestFactory();
    }

  }



}
