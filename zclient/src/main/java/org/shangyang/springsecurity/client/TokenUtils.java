package org.shangyang.springsecurity.client;

import org.apache.tomcat.util.codec.binary.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestTemplate;

public class TokenUtils {
	
	protected static final Logger logger = LoggerFactory.getLogger(TokenUtils.class);	
	
	/**
	 * the util method to get the access code by using authorization code;
	 * 
	 * @param parameters, the parameters in post body; 
	 * @param clientId
	 * @param clientSecret
	 * @param requestUri
	 * @return
	 */
	public static String postForAccessCode(JSONObject parameters, String clientId, String clientSecret, String requestUri) {
		
	    RestTemplate rest = new RestTemplate();
	    
	    HttpHeaders headers = new HttpHeaders();
	    
	    headers.setContentType(MediaType.APPLICATION_JSON);
	    
	    headers.add("authorization", getBasicAuthHeader( clientId, clientSecret ));

	    HttpEntity<JSONObject> entity = new HttpEntity<JSONObject>( parameters, headers );
	    
	    ResponseEntity<OAuth2AccessToken> resp = rest.postForEntity( requestUri, entity, OAuth2AccessToken.class );
	    
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
	
}
