package org.shangyang.springsecurity.client;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestTemplate;

public class TokenUtils {
	
	protected static final Logger logger = LoggerFactory.getLogger(TokenUtils.class);	
	
	protected static final RestTemplate REST_TEMPLATE = new RestTemplate();
	
	/**
	 * the util method to get the access code by using authorization code;
	 * 
	 * @param parameters, the parameters in post body; 
	 * @param clientId
	 * @param clientSecret
	 * @param requestUri
	 * @return
	 */
	public static <T> String postForAccessCode( T parameters, String clientId, String clientSecret, String requestUri) {
		
	    
	    
	    HttpHeaders headers = new HttpHeaders();
	    
	    // headers.setContentType(MediaType.TEXT_PLAIN);	    
	    
	    headers.add("authorization", getBasicAuthHeader( clientId, clientSecret ));

	    HttpEntity<T> entity = new HttpEntity<T>( parameters, headers );
	    
	    ResponseEntity<OAuth2AccessToken> resp = REST_TEMPLATE.postForEntity( requestUri, entity, OAuth2AccessToken.class );
	    
	    if( !resp.getStatusCode().equals( HttpStatus.OK )){
	    	
	    	throw new RuntimeException( resp.toString() );
	    }
	    
	    OAuth2AccessToken t = resp.getBody();
	    
	    logger.debug("the response, access_token: " + t.getValue() +"; token_type: " + t.getTokenType() +"; "
	    		+ "refresh_token: " + t.getRefreshToken() +"; expiration: " + t.getExpiresIn() +", expired when:" + t.getExpiration() );			
		
	    return t.getValue();		
		
		
	}

	
	public static String getBasicAuthHeader(String clientId, String clientSecret){
		
        String auth = clientId + ":" + clientSecret;
        
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes());
        
        String authHeader = "Basic " + new String(encodedAuth);
        
        return authHeader;
	}


	public static <T> T getForProtectedResource(String accessToken, Class<T> clazz, String requestUri) {
	    
	    HttpHeaders headers = new HttpHeaders();
	    
	    headers.add( "authorization", "Bearer " + accessToken );

	    HttpEntity<String> entity = new HttpEntity<String>(null, headers);
		
	    // pay attention, if using get with headers, should use exchange instead of getForEntity / getForObject
	    ResponseEntity<T> resp = REST_TEMPLATE.exchange( requestUri, HttpMethod.GET, entity, clazz, new Object[]{ null } );
	    
	    return resp.getBody();		
		
	}	
	
}
