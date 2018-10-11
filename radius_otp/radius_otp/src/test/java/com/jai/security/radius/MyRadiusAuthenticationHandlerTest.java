package com.jai.security.radius;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import org.jasig.cas.adaptors.radius.JRadiusServerImpl;
import org.jasig.cas.adaptors.radius.RadiusClientFactory;
import org.jasig.cas.adaptors.radius.RadiusProtocol;
import org.jasig.cas.adaptors.radius.RadiusServer;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.junit.Test;

/**
 * Test case to test RadiusAuthentication
 * 
 * 
 * @author jjayaraman
 *
 */
// @Ignore
public class MyRadiusAuthenticationHandlerTest {

	MyRadiusAuthenticationHandler radiusAuthenticationHandler = new MyRadiusAuthenticationHandler();

	List<RadiusServer> servers = new ArrayList<RadiusServer>();

	private final String USER = "user";

	private final String PASSWORD = "pass";

	private final String OTP = "12345678";

	private final String RADIUS_HOST = "";

	private final String SECRET = "secret";

	@Test
	public void testAuthenticateUsernamePasswordInternalUsernamePasswordCredential()
			throws GeneralSecurityException, PreventedException {

		OTPUsernamePasswordCredential credential = new OTPUsernamePasswordCredential(USER, PASSWORD, OTP);

		RadiusClientFactory radiusClientFactory = new RadiusClientFactory();
		radiusClientFactory.setInetAddress(RADIUS_HOST);
		radiusClientFactory.setSharedSecret(SECRET);

		RadiusServer radiusServer = new JRadiusServerImpl(RadiusProtocol.PAP, radiusClientFactory);
		servers.add(radiusServer);

		radiusAuthenticationHandler.setServers(servers);
		HandlerResult result = radiusAuthenticationHandler.authenticateUsernamePasswordInternal(credential);

		System.out.println("Principal : " + result.getPrincipal());
		System.out.println("Principal : " + result.getHandlerName());
		System.out.println("Principal : " + result.getCredentialMetaData());

		System.out.println("Done...");
	}

}
