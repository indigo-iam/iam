package it.infn.mw.tc;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.stream.Collectors.joining;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.config.ServerConfiguration;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;

public class IamAuthRequestOptionsService implements AuthRequestOptionsService {

  IamClientConfig properties;


  public IamAuthRequestOptionsService(IamClientConfig properties) {
    this.properties = properties;
  }

  private String sanitizeScope(String scope, RegisteredClient client) {
    List<String> requestedScopes = Splitter.on(" ").splitToList(scope);
    return requestedScopes.stream().filter(client.getScope()::contains).collect(joining(" "));
  }

  @Override
  public Map<String, String> getOptions(ServerConfiguration server, RegisteredClient client,
      HttpServletRequest request) {
    Map<String, String> options = new HashMap<>();

    if (!isNullOrEmpty(properties.getExtAuthnHint())) {
      options.put("ext_authn_hint", properties.getExtAuthnHint());
    }

    if (request.getParameter("scope") != null) {
      String sanitizedScope = sanitizeScope(request.getParameter("scope"), client);

      if (!Strings.isNullOrEmpty(sanitizedScope)) {
        options.put("scope", sanitizedScope);
      }

    }

    return options;
  }

  @Override
  public Map<String, String> getTokenOptions(ServerConfiguration server, RegisteredClient client,
      HttpServletRequest request) {

    return Collections.emptyMap();
  }

}
