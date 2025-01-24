package it.infn.mw.iam.core.oidc;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * This class sets a timestamp on the current HttpSession
 * when someone successfully authenticates
 */
@Component("authenticationTimeStamper")
public class AuthenticationTimeStamper extends SavedRequestAwareAuthenticationSuccessHandler {

    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationTimeStamper.class);

    public static final String AUTH_TIMESTAMP = "AUTH_TIMESTAMP";

    /**
     * Set the timestamp on the session to mark when the authentication happened,
     * useful for calculating authentication age. This gets stored in the session
     * and can get pulled out by other components.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        Date authTimestamp = new Date();

        HttpSession session = request.getSession();

        session.setAttribute(AUTH_TIMESTAMP, authTimestamp);

        if (session.getAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED) != null) {
            session.setAttribute(AuthorizationRequestFilter.PROMPTED, Boolean.TRUE);
            session.removeAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED);
        }

        logger.info("Successful Authentication of " + authentication.getName() + " at " + authTimestamp.toString());

        super.onAuthenticationSuccess(request, response, authentication);

    }

}