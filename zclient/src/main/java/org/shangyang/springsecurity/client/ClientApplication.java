package org.shangyang.springsecurity.client;

import javax.servlet.http.HttpSession;

import org.json.JSONObject;
import org.shangyang.springsecurity.commons.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 
 * @author shangyang
 *
 */
@SpringBootApplication
@Controller
public class ClientApplication {

	protected static final Logger logger = LoggerFactory.getLogger(ClientApplication.class);
	
	public static void main(String[] args) {
		
		SpringApplication.run(ClientApplication.class, args);
	}
	
	/**
	 * 用来验证通过 Authorization Code 的授权方式；
	 * 
	 * @param model
	 * @return
	 */
    @RequestMapping( value = "/", method = RequestMethod.GET )
	public String index(HttpSession session, ModelMap model){
		
    	String state =  String.valueOf( System.currentTimeMillis() );
    	
    	model.addAttribute("state", state);
    	
    	session.setAttribute("state", state);
    	
    	return "index";
    	
	}
    
    /**
     * 
     * @param model
     * @param code -> the authorization code responsed from authorization server
     * @param state
     * @return
     */
    @RequestMapping( value = "/access", method = RequestMethod.GET )
	public String access(HttpSession session, ModelMap model, String code, String state){
		
    	logger.debug("code="+code+", state="+state);
    	
    	if( !org.apache.commons.lang3.StringUtils.equals(state, session.getAttribute("state").toString() ) ){
    		throw new RuntimeException("CSRF attack! the state token value is NOT equals；");
    	}
    	
//      使用下面的 JSONObject 在解析参数的时候生死都要报错，RestClientException: Could not write request: no suitable HttpMessageConverter found for request type [org.json.JSONObject]
//    	从错误信息中可以知道 JSONObject 不能被解析；所以退而求其次，使用 MultiValueMap 来替代了；
//    	
//    	JSONObject parameters = new JSONObject();
//    	
//    	parameters.put("grant_type", "authorization_code");
//    	parameters.put("code", code);
//    	
//    	logger.debug("==========> " + parameters.toString());
    	
    	MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
    	
    	parameters.add("grant_type", "authorization_code");
    	parameters.add("code", code);
    	// 照理说，我获取 access_token 不需要 redirect_uri 参数，但是这里必须与获取 authorization_code 的 redirect_uri 保持一致，我想，是出于安全考虑吧；
    	parameters.add("redirect_uri", "http://localhost:8080/client/access"); 
    	
    	// 通过 Authorization Code 获取 Access Token；
    	String accessToken = TokenUtils.postForAccessCode( parameters, "c1", "password", "http://localhost:9999/uaa/oauth/token" );
    	
    	logger.debug("==========> access token retrieved, " + accessToken);    	
    	
    	// 通过 Access Token 获取 Resource Server 上的被保护资源；
    	
    	User user = TokenUtils.getForProtectedResource( accessToken, User.class, "http://localhost:9999/uaa/api/user/1000" );
    	
    	logger.debug("=========> protected user retrieved: " + user.toString() );
    	
    	model.addAttribute("user", user);
    	
    	return "access";
    	
	}
    
    /**
     * 
     * Client 为什么也要添加 Web Security 的相关配置？
     * 
     * 照理说，Client 作为一个纯的客户端，当然不需要 Spring Security 任何相关的东西；但是因为在 {@link TokenUtils#postForAccessCode(JSONObject, String, String, String)} 中使用到了 
     * @see OAuth2AccessToken 对象，那么就必须使用到 spring-security-oauth2 library；那么问题来了，只要一通过 Maven 将此 library 载入，那么它就会自动的将默认的 Web Security 给载入；
     * 
     * 想到了两种解决办法，
     * 
     * 1. 使用 Spring Boot 载入的时候，将 WebSecurity 相关的 Configuration Bean 给过滤掉； 
     * 2. 配置一个允许所有链接访问的 Web Security；
     * 
     * 这里我采用第二种解决办法；
     * 
     * @author shangyang
     *
     */
    @Configuration
    @EnableWebSecurity
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    	
        @Override
        protected void configure(HttpSecurity http) throws Exception {
        	
            http
            		.authorizeRequests().antMatchers("/**").permitAll();

            
        }
    }
	
}
