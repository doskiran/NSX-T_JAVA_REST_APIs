import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import sun.misc.BASE64Encoder;

public class NSXTManagerRestAPI {
	String ipaddress = null;
	String username = null;
	String password = null;

	public NSXTManagerRestAPI(String ipaddress, String username, String password) {
		this.ipaddress = ipaddress;
		this.username = username;
		this.password = password;
	}

	static {
		disableSslVerification();
	}

	private static void disableSslVerification() {
		try {
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}

				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			} };
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			// Create all-trusting host name verifier
			HostnameVerifier allHostsValid = new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
	}

	public HttpHeaders getAuthenticationHeader() throws Exception {
		String authString = username + ":" + password;
		String base64Creds = new BASE64Encoder().encode(authString.getBytes());
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Basic " + base64Creds);
		return headers;
	}

	/**
	 * This method is used to returns information about all configured logical
	 * switches.
	 * 
	 * @return
	 * @throws Exception
	 */
	public String getLogicalSwitches() throws Exception {
		String response = null;
		RestTemplate restTemplate = new RestTemplate();
		try {
			String url = "https://" + ipaddress + "/api/v1/logical-switches/";
			HttpEntity<String> getReq = new HttpEntity<>("", getAuthenticationHeader());
			ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET, getReq, String.class);
			response = responseEntity.getBody();
			System.out.println("Response::" + response);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return response;
	}

	/**
	 * This method is used to returns information about the NSX cluster
	 * configuration.
	 * 
	 * @return
	 * @throws Exception
	 */
	public String readClusterConfiguration() throws Exception {
		String response = null;
		RestTemplate restTemplate = new RestTemplate();
		try {
			String url = "https://" + ipaddress + "/api/v1/cluster/";
			HttpEntity<String> getReq = new HttpEntity<>("", getAuthenticationHeader());
			ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET, getReq, String.class);
			response = responseEntity.getBody();
			System.out.println("Response::" + response);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return response;
	}

	public static void main(String[] args) throws Exception {

		String ipaddress = "10.10.10.10"; // NSX-T Manager IPaddress
		String username = "admin"; // Username
		String password = "kfweriofnuecviuvbeiu"; // Password

		NSXTManagerRestAPI nsxtApi = new NSXTManagerRestAPI(ipaddress, username, password);

		nsxtApi.getLogicalSwitches();

		nsxtApi.readClusterConfiguration();

	}

}
