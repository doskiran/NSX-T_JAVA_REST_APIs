import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

import org.codehaus.jackson.annotate.JsonProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import sun.misc.BASE64Encoder;

/**
 * This class is used to Register compute manager(vCenter) with NSX-T Manager
 * 
 * @author Kiran Kumar P
 *
 */
public class RegisterComputeManagerWithNSX {

	String ipaddress = null;
	String username = null;
	String password = null;

	public RegisterComputeManagerWithNSX(String ipaddress, String username, String password) {
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

	/**
	 * This method is used to get the host SHA-256 thumbprint
	 * 
	 * @param hostName
	 * @return
	 * @throws UnknownHostException
	 * @throws IOException
	 * @throws CertificateNotYetValidException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws CertificateEncodingException
	 */
	public String getSHA256ThumbPrint(String hostName)
			throws UnknownHostException, IOException, CertificateNotYetValidException, NoSuchAlgorithmException,
			KeyManagementException, CertificateEncodingException {
		String thumbprint = null;
		SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
		X509TrustManager trustManager = new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};
		sslContext.init(null, new TrustManager[] { trustManager }, null);
		SSLSocketFactory ssf = sslContext.getSocketFactory();
		SSLSocket sslSocket = (SSLSocket) ssf.createSocket(hostName, 443);
		sslSocket.startHandshake();
		Certificate[] certificateChain = sslSocket.getSession().getPeerCertificates();
		for (Certificate cert : certificateChain) {
			System.out.println("Certificate:: " + cert);
			if (cert instanceof X509Certificate) {
				try {
					((X509Certificate) cert).checkValidity();
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					byte[] der = cert.getEncoded();
					md.update(der);
					byte[] digest = md.digest();
					String digestHex = DatatypeConverter.printHexBinary(digest);
					thumbprint = digestHex.toLowerCase().replaceAll("..(?!$)", "$0:");
					System.out.println("Thumbprint::" + thumbprint);
				} catch (CertificateExpiredException e) {
					System.out.println("Certificate is expired..." + e);
				}
			}
		}
		return thumbprint;
	}

	public HttpHeaders getAuthenticationHeader() throws Exception {
		String authString = username + ":" + password;
		String base64Creds = new BASE64Encoder().encode(authString.getBytes());
		HttpHeaders headers = new HttpHeaders();
		headers.add("Accept", "application/json");
		headers.add("Content-Type", "application/json");
		headers.add("Authorization", "Basic " + base64Creds);
		return headers;
	}

	@org.codehaus.jackson.annotate.JsonIgnoreProperties(ignoreUnknown = true)
	public static class ComputeManager {
		@JsonProperty("display_name")
		private String display_name;

		@JsonProperty("server")
		private String server;

		@JsonProperty("origin_type")
		private String origin_type;

		@JsonProperty("credential")
		private Credential Credential;

		@JsonProperty("resource_type")
		private String resource_type;

		public String getResource_type() {
			return resource_type;
		}

		public void setResource_type(String resource_type) {
			this.resource_type = resource_type;
		}

		public String getDisplay_name() {
			return display_name;
		}

		public void setDisplay_name(String display_name) {
			this.display_name = display_name;
		}

		public Credential getCredential() {
			return Credential;
		}

		public void setCredential(Credential credential) {
			Credential = credential;
		}

		public String getServer() {
			return server;
		}

		public void setServer(String server) {
			this.server = server;
		}

		public String getOrigin_type() {
			return origin_type;
		}

		public void setOrigin_type(String origin_type) {
			this.origin_type = origin_type;
		}
	}

	@org.codehaus.jackson.annotate.JsonIgnoreProperties(ignoreUnknown = true)
	public static class Credential {
		@JsonProperty("credential_type")
		private String credential_type;

		@JsonProperty("username")
		private String username;

		@JsonProperty("password")
		private String password;

		@JsonProperty("thumbprint")
		private String thumbprint;

		public String getCredential_type() {
			return credential_type;
		}

		public void setCredential_type(String credential_type) {
			this.credential_type = credential_type;
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		public String getThumbprint() {
			return thumbprint;
		}

		public void setThumbprint(String thumbprint) {
			this.thumbprint = thumbprint;
		}
	}

	public ComputeManager setComputemanager(String server, String username, String password, String thumbprint)
			throws Exception {
		ComputeManager computeManager = new ComputeManager();
		try {
			computeManager.setServer(server);
			computeManager.setOrigin_type("vCenter");
			Credential credential = new Credential();
			credential.setUsername(username);
			credential.setPassword(password);
			credential.setThumbprint(thumbprint);
			credential.setCredential_type("UsernamePasswordLoginCredential");
			computeManager.setCredential(credential);
			computeManager.setResource_type("ComputeManager");
			computeManager.setDisplay_name("VC-" + server);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return computeManager;
	}

	/**
	 * This method is used to Register compute manager(vCenter) with NSX
	 * 
	 * @param computemanager
	 * @return
	 * @throws Exception
	 */
	public String registerComputeManagerWithNSX(ComputeManager computemanager) throws Exception {
		RestTemplate restTemplate = new RestTemplate();
		String response = null;
		try {
			String url = "https://" + ipaddress + "/api/v1/fabric/compute-managers/";
			HttpEntity<ComputeManager> postReq = new HttpEntity<ComputeManager>(computemanager,
					getAuthenticationHeader());
			ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.POST, postReq, String.class);
			response = responseEntity.getBody();
			System.out.println("Response::" + response);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return response;
	}

	public static void main(String[] args) throws Exception {

		String ipaddress = "10.10.10.20"; // NSX-T Manager IPaddress
		String username = "admin"; // Username
		String password = "fsdfsdgdgdfg"; // Password

		String vcIPaddress = "20.20.20.30"; // vCenter IPaddress
		String vcUsername = "Administrator@vsphere.local"; // Username
		String vcPassword = "sdfsdvdfvdfbvd"; // Password

		RegisterComputeManagerWithNSX addVcenter = new RegisterComputeManagerWithNSX(ipaddress, username, password);
		// Note: To generate thumbprint by yourself follow the steps provided in
		// NSX-T Data Center REST API Reference
		String thumbPrint = addVcenter.getSHA256ThumbPrint(vcIPaddress);
		ComputeManager computeManager = addVcenter.setComputemanager(vcIPaddress, vcUsername, vcPassword,
				thumbPrint.trim());
		addVcenter.registerComputeManagerWithNSX(computeManager);
	}

}
