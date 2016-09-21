/*
      Copyright 2016 sehawagn/friesenkiwi/pokerazor/Hanno - Felix Wagner

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package de.unidue.stud.sehawagn.oidcclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

//import org.keycloak.client.registration.ClientRegistrationException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

/*
 * This is a sample client to test out and debug an OpenID Connect Provider (OP) such as the Keycloak server.
 * It is aimed for native clients (as opposed to web clients).
 * It authenticates the client by secret and the user by username/password (also called Resource Owner Credentials Grant or Direct Access in Keycloak) or by a session copied from the browser and an Authorization Code, implemented as Explicit Code Flow.
 * It then retrieves and displays Access Token, ID Token and UserInfo, as well as passing the access token to a Relying Party and accessing/displaying the protected resource.
 * Dynamic client registration and Dynamic Obtaining of OpenID Provider Configuration is supported as well.
 * 
 * Don't use this unaltered in a production environment! The https security is completely overridden and it is a very bad idea to store user or client credentials in code, this is only been done here for training and clarity of example
 */

public class KeyCloakExampleClient {

	private static final String KEYCLOAK_AUTH_PATH = "/auth";
	private static final String KEYCLOAK_AUTH_ENDPOINT_PATH = "protocol/openid-connect/auth";
	private static final String KEYCLOAK_USERINFO_ENDPOINT_PATH = "protocol/openid-connect/userinfo";

	private static String keycloakRealm = "";

	private static String keycloakServer = "";
	private static String keycloakRealmPath = "";

	private static String openIDConnectProviderURI = "";

	private static String providerMetadataJSON = "";

	private static String keycloakSessionCookie = "";
	private static String staticAuthenticationRequestURL = "";

	private static String initialAccessTokenString = "";

	private static String relyingPartyServer = "";
	private static String relyingPartyResource = "";

	private static String clientID = "";
	private static String clientSecret = "";
	private static String clientRedirectURL = "";

	private static String userPassword = "";
	private static String userName = "";

	private static SimpleOIDCClient oidcClient = null;

	// use https://jwt.io/ for Token debugging

/*
	The basic authentication flow in OpenID Connect consists of the following steps:

	  1.  Optional: OpenID Provider Issuer Discovery using WebFinger
	  2.  Optional: Obtaining OpenID Provider Configuration Information
	  3.  Optional: Dynamic client registration
	  4.  Authentication (using one of the defined flows)
	  5.  Optional: Token request
	  6.  Optional: UserInfo request
*/

	public static void main(String[] args) {
		init();

		try {
			doResourceAccess();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SerializeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
/*		} catch (ClientRegistrationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
*/		}
	}

	public static void init() {

		// SECURITY BREACH!!! !!NEVER!! use this on production systems, only for debugging
		// get certificates for Keycloak and relying party server e.g. from Let's Encrypt

		// always trust everybody (don't validate certificate or host names), this is necessary, because the OIDC library creates it's own HTTPS connections
		SimpleOIDCClient.trustEverybody(null);
		// SECURITY BREACH!!! !!NEVER!! use this on production systems, only for debugging

		keycloakRealm = "$REALM"; // set at https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$KEYCLOAK_REALM

		keycloakServer = "https://keycloak.example.com/"; // your Keycloak host/port (including https:// prefix), e.g. Keycloak
		keycloakRealmPath = KEYCLOAK_AUTH_PATH + "/realms/" + keycloakRealm + "/";
		openIDConnectProviderURI = keycloakServer + keycloakRealmPath; // override if not using Keycloak

		// only if not automatically retrieved, get this from https://$KEYCLOAK_SERVER/auth/realms/$KEYCLOAK_REALM/.well-known/openid-configuration
		providerMetadataJSON = "{\"issuer\":\"https://keycloak.example.com/auth/realms/$REALM\",\"authorization_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/auth\",\"token_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/token\",\"token_introspection_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/token/introspect\",\"userinfo_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/userinfo\",\"end_session_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/logout\",\"jwks_uri\":\"https://keycloak.example.com/auth/realms/$REALM/protocol/openid-connect/certs\",\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\"],\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"registration_endpoint\":\"https://keycloak.example.com/auth/realms/$REALM/clients-registrations/openid-connect\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"private_key_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":false,\"scopes_supported\":[\"openid\",\"offline_access\"],\"request_parameter_supported\":false,\"request_uri_parameter_supported\":false}";

		// only for debugging if using session hijacking, get this from browser (e.g. F12 in Firefox)
		keycloakSessionCookie = "KC_RESTART=eyJhbGciO...; KEYCLOAK_LOCALE=en; KEYCLOAK_STATE_CHECKER=Su_z_Hnoi...; KEYCLOAK_IDENTITY=eyJhbGciO...; KEYCLOAK_SESSION=$REALM/.../...";
		// only for debugging if doing MITM, get this from browser
		staticAuthenticationRequestURL = "https://example.com/testredirect?state=...&code=...";

		// only if using dynamic client registration, get this from https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$KEYCLOAK_REALM/client-initial-access
		initialAccessTokenString = "eyJhbGciO...";

		// the host/port/path of the resource protected by OpenID Connect
		relyingPartyServer = "https://relying.example.com"; // get these from your Relying Party
		relyingPartyResource = "/protected-resource/"; // get these from your Relying Party

		clientID = "testclient"; // get this from https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$REALM/clients/$CLIENT
		clientSecret = "..."; // get this from https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$REALM/clients/$CLIENT/credentials

		clientRedirectURL = relyingPartyServer + relyingPartyResource;
		// scheme://localhost/redirect // https://example.com/testredirect // TODO think about a reasonable redirect URL for a native application
//		clientRedirectURL = "https://keycloak.example.com/auth/realms/$REALM/account/"; // only for debugging, Keycloak account view/client, set like https://$KEYCLOAK_SERVER/auth/realms/$REALM/account/ 

		userName = "testuser"; // set/get this from https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$REALM/users/$USER
		userPassword = "test"; // set/get this from https://$KEYCLOAK_SERVER/auth/admin/master/console/#/realms/$REALM/users/$USER/user-credentials

		oidcClient = new SimpleOIDCClient();
	}

	public static void doProvisioning() throws URISyntaxException, ParseException, IOException, SerializeException { //, ClientRegistrationException {
		stepOne();
		stepTwo();
		stepThree();
	}

	public static void doResourceAccess() throws ParseException, URISyntaxException, IOException, SerializeException { //, ClientRegistrationException {
		String authRedirection = "";
		AccessToken accessToken = null;

		doProvisioning();

		System.out.println("try a direct access to the resource");
		authRedirection = stepSix(accessToken);

		if (authRedirection == null) { 	// no authentication required (or already authenticated?)
			System.out.println("resource available");
			return;
		}

		System.out.println("authentication redirection neccessary");
		stepFour(authRedirection);

		accessToken = stepFive();

		System.out.println("access the resource again, this time sending an access token");
		authRedirection = stepSix(accessToken);
		if (authRedirection == null) { 	// no authentication required (or already authenticated?)
			System.out.println("resource available");
			System.out.println("the logged in resource should be shown");
			return;
		} else {
			System.err.println("Something went awfully wrong");
			return;
		}
	}

	// Optional: OpenID Provider Issuer Discovery using WebFinger
	// Alternatively: provide issuer URI manually
	public static void stepOne() throws URISyntaxException {
//		oidcClient.lookupOpenIDProvider(); // done out-of-band (see below) // using WebFinger, see https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery

		oidcClient.setIssuerURI(openIDConnectProviderURI); // could be skipped by explicit providerMetadataJson
	}

	// Optional: Obtaining OpenID Provider Configuration Information
	// Alternatively: provide metadata manually
	public static void stepTwo() throws URISyntaxException, ParseException, IOException {
		oidcClient.setAuthorizationEndpointURI(openIDConnectProviderURI + KEYCLOAK_AUTH_ENDPOINT_PATH);	// overridden by retrieveProviderMetadata() or out-of-band by setProviderMetadata()
		oidcClient.setUserInfoEndpointURI(openIDConnectProviderURI + KEYCLOAK_USERINFO_ENDPOINT_PATH); // overridden by retrieveProviderMetadata() or out-of-band by setProviderMetadata(), only used in step six

		oidcClient.setProviderMetadata(providerMetadataJSON); // overridden by retrieveProviderMetadata(), setting metadata manually and statically, mainly for debugging,

		oidcClient.retrieveProviderMetadata();  // from .well-known/openid-configuration
	}

	// Optional: Dynamic client registration
	// Alternatively: Provide client data manually
	public static void stepThree() throws ParseException, URISyntaxException, SerializeException, IOException { //, ClientRegistrationException {
//		doClientRegistrationKeycloak();  // only in case of dynamic client registration // FIMXME not working yet

//		doClientConfiguration(true);
//		doClientRegistrationConnect2ID(); // only in case of dynamic client registration

		/*
		 * only in case of dynamic client registration
		 * may also be done via command line
		 * see http://connect2id.com/products/server/docs/guides/client-registration#access
		 * or  https://access.redhat.com/documentation/en/red-hat-single-sign-on/7.0/paged/securing-applications-and-services-guide/chapter-4-client-registration
		curl \
		--insecure \
		-X POST \
		-d '{  }' \
		-H "Content-Type:application/json" \
		-H "Authorization: bearer eyJhbGciOi..." \
		https://keycloak.example.com/auth/realms/$REALM/clients-registrations/openid-connect
		 */

		doClientConfiguration(false); // set basic client parameters
	}

	// Authentication (using one of the defined flows)
	// Alternatively: Do direct access via username/password
	public static void stepFour(String authRedirection) throws ParseException, URISyntaxException, SerializeException, IOException {
//		System.out.println("authenticate USER and CLIENT (native application)");

//		doAuthorizationCodeAccess(authRedirection);

		doResourceOwnerCredentialsAccess(authRedirection);
	}

	// Optional: Token request
	public static AccessToken stepFive() {
//		System.out.println("commence authorization, retrieve access token");

		oidcClient.requestToken();

		AccessToken accessToken = oidcClient.getAccessToken();
		return accessToken;
	}

	// Optional: UserInfo request
	// Alternatively: pass Access Token on to another client, use it to access a resource there
	public static String stepSix(AccessToken accessToken) throws ParseException, IOException {
		if (accessToken != null) {
			oidcClient.dumpTokenInfo();
			// only for debugging
			oidcClient.requestUserInfo();
			System.out.println("UserInfoJSON:");
			System.out.println(oidcClient.getUserInfoJSON());
		}
		return processURL(oidcClient.getRedirectURI().toURL(), accessToken, null);
	}

	public static void doClientConfiguration(boolean registration) throws ParseException, URISyntaxException {
//		System.out.println("set CLIENT authentication parameters");
		if (registration) {
			oidcClient.setClientRegistrationMetadata(clientRedirectURL);
		} else {
			oidcClient.setClientMetadata(clientRedirectURL);
		}
		oidcClient.setClientID(clientID, clientSecret);
		oidcClient.setRedirectURI(clientRedirectURL);
	}

	// optional dynamic client registration (via connect2ID library)
	public static void doClientRegistrationConnect2ID() throws SerializeException, ParseException, IOException {
		BearerAccessToken initialAccessToken = new BearerAccessToken(initialAccessTokenString);
		oidcClient.registerClient(initialAccessToken);
	}
/*
	// optional dynamic client registration (via Keycloak library)
	// FIXME doesn't work (false/null error)
	public static void doClientRegistrationKeycloak() throws ClientRegistrationException {
		SimpleOIDCClient.registerClientKeycloak(clientID, initialAccessTokenString, keycloakServer + KEYCLOAK_AUTH_PATH, keycloakRealm);
	}
*/
	public static void doResourceOwnerCredentialsAccess(String authRedirection) throws ParseException, URISyntaxException {
//		System.out.println("parse authentication parameters from redirection");
		oidcClient.parseAuthenticationDataFromRedirect(authRedirection, false); // don't override clientID (what are the caveats of both ways?)

//		System.out.println("set USER credentials");
		oidcClient.setResourceOwnerCredentials(userName, userPassword);
	}

	public static void doAuthorizationCodeAccess(String authRedirection) throws SerializeException, IOException, ParseException, URISyntaxException {
		URL authenticationRequestURL;

//		authenticationRequestURL = getStaticAuthorizationCodeRequest(); // only for debugging purposes

		authenticationRequestURL = getAuthorizationCodeRequest(authRedirection);

//		processURL(authenticationRequestURL, null, null); // not really possible, because some kind of login is required first
		String redirectionURL = doSessionHijackingLogin(authenticationRequestURL);

		oidcClient.processAuthenticationResponse(redirectionURL); // state validation will fail (because...?)
	}

	public static URL getStaticAuthorizationCodeRequest() throws MalformedURLException {
		return new URL(staticAuthenticationRequestURL);
	}

	public static URL getAuthorizationCodeRequest(String authRedirection) throws MalformedURLException, SerializeException, ParseException, URISyntaxException {
		oidcClient.parseAuthenticationDataFromRedirect(authRedirection, true);

		return oidcClient.buildAuthorizationCodeRequest().toURL();
	}

	public static String doSessionHijackingLogin(URL authenticationRequestURL) throws IOException {
		return processURL(authenticationRequestURL, null, keycloakSessionCookie);
	}

	public static String processURL(URL requestURL, AccessToken accessToken, String keycloakSessionCookie) throws IOException {
		String redirectionURL = "";

//		System.out.println("requestURL=");
//		System.out.println(requestURL);

		HttpURLConnection.setFollowRedirects(false);

		HttpsURLConnection conn = (HttpsURLConnection) requestURL.openConnection();
		SimpleOIDCClient.trustEverybody(conn);
		conn.setRequestMethod("GET");
		if (accessToken != null) {
			conn.setRequestProperty("Authorization", "bearer " + accessToken);
		} else if (keycloakSessionCookie != null) { // only for debugging
			conn.setRequestProperty("Cookie", keycloakSessionCookie);
		}

		conn.connect();

		int responseCode = conn.getResponseCode();

		if (responseCode == 302) {
			redirectionURL = conn.getHeaderField("Location");
//			System.out.println("redirection to:");
//			System.out.println(redirectionURL);
			return redirectionURL;
		} else if (responseCode == 400) {
			System.err.println("400: General Error");
			return null;
		} else if (responseCode == 500) {
			System.err.println("500");
			return null;
		} else if (responseCode == 200) { //
			BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				System.out.println(inputLine);
			}
			in.close();
			return null;
		} else {
			System.err.println("responseCode =" + responseCode);
			return null;
		}
	}
}