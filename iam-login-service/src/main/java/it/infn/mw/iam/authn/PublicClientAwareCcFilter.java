package it.infn.mw.iam.authn;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;

import it.infn.mw.iam.api.client.service.ClientService;

public class PublicClientAwareCcFilter extends ClientCredentialsTokenEndpointFilter {

    private final ClientService clientService;

    public PublicClientAwareCcFilter(String tokenEndpoint, ClientService clientService) {
        super(tokenEndpoint);
        this.clientService = clientService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        String clientId = request.getParameter("client_id");

        if (clientId != null) {
            Optional<ClientDetailsEntity> client = clientService.findClientByClientId(clientId);

            // Bypass only for public clients
            if (client.isPresent() &&
                    client.get().getTokenEndpointAuthMethod() == AuthMethod.NONE) {
                return new UsernamePasswordAuthenticationToken(clientId, "", Collections.emptyList());
            }
        }

        // Default behavior for confidential clients
        return super.attemptAuthentication(request, response);
    }
}
