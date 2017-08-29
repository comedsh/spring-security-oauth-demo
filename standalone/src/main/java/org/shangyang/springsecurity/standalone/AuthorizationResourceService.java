package org.shangyang.springsecurity.standalone;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * 
 * Standalone Server with Authorization Service and Resource Service all together;
 * 
 * @author shangyang
 *
 */

@SpringBootApplication
@RestController
public class AuthorizationResourceService {

	public static void main(String[] args) {
		
		SpringApplication.run(AuthorizationResourceService.class, args);
	}
	
    // 配置 URL 到 view 之间的映射
    @Configuration
    static class MvcConfig extends WebMvcConfigurerAdapter {
        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("login").setViewName("login");
        }
    }	
    
    @Configuration
    @EnableWebSecurity
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    	
        @Override
        protected void configure(HttpSecurity http) throws Exception {
        	
            http
            		.authorizeRequests()
            		/**
            		 * /oauth/authorize -> authorization code 授权模式的登录入口地址，通常是从 client 将 resource owner 重定向到 authorization server 进行验证的入口地址；
            		 * /oauth/confirm_access -> authorization code 授权模式的确认页面，当 resource owner 输入自己的 credentials 以后，会跳转到该页面询问用户是否确认授权？confirm or deny；
            		 */
            		.antMatchers("/", "/login", "/oauth/authorize", "/oauth/confirm_access").permitAll()
            		
            	.and()
	            	.authorizeRequests()
	            	.anyRequest().authenticated()
	            	
            	.and()
		        	.formLogin()
		    		.loginPage("/login");
            
        }
    }
    
	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}
		
		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security.checkTokenAccess("isAuthenticated()");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("c1")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .resourceIds("oauth2-resource")
		            .accessTokenValiditySeconds(600)
 		    .and()
		        .withClient("c2")
		            .authorizedGrantTypes("authorization_code")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "trust")
		            .resourceIds("oauth2-resource")
		            .redirectUris("http://anywhere?key=value")
 		    .and()
		        .withClient("c3")
		            .authorizedGrantTypes("client_credentials", "password")
		            .authorities("ROLE_CLIENT")
		            .scopes("read")
		            .resourceIds("oauth2-resource")
		            .secret("secret");
		// @formatter:on
		}

	}
	
	@Configuration
	@EnableResourceServer
    static class ResourceServerConfig extends ResourceServerConfigurerAdapter{
	
        @Override
        public void configure(HttpSecurity http) throws Exception {
        	
            http.antMatcher("/api/**") // the filter chain defined for restful
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/api/user/{id}").access("hasRole('CUSTOMER') and #oauth2.hasScope('read')");
            		
        }
        
	}
	
	/**
	 * 该资源是被保护的 Resource 资源；只有拿到 Access Token 以后，才能获取；
	 * 
	 * @param id
	 * @return
	 */
    @RequestMapping( value = "/api/user/{id}", method = RequestMethod.GET )
    public ResponseEntity<User> getTransaction(@PathVariable("id") long id){
    	
    	User user = new User();
    	
    	return new ResponseEntity<User>( user, HttpStatus.OK );
    	
    }
    
    /**
     * just a demo
     *  
     * @author shangyang
     *
     */
    class User{
    	
    	String username = "test";
    	
    	String hobbies = "reading, driving ....";

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getHobbies() {
			return hobbies;
		}

		public void setHobbies(String hobbies) {
			this.hobbies = hobbies;
		}
    	
    }
}
