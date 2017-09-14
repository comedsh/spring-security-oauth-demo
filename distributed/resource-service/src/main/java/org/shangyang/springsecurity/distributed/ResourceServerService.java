package org.shangyang.springsecurity.distributed;

import org.shangyang.springsecurity.commons.User;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * 
 * Standalone Server with Authorization Service and Resource Service all together;
 * 
 * @author shangyang
 *
 */

@SpringBootApplication
@RestController
public class ResourceServerService {

	public static void main(String[] args) {
		
		SpringApplication.run(ResourceServerService.class, args);
	}
	
    
//    @Configuration
//    @EnableWebSecurity
//    @Order(10)
//    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//    	
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//        	
//            http
//            		.authorizeRequests()
//            		/**
//            		 * /oauth/authorize -> authorization code 授权模式的登录入口地址，通常是从 client 将 resource owner 重定向到 authorization server 进行验证的入口地址；
//            		 * /oauth/confirm_access -> authorization code 授权模式的确认页面，当 resource owner 输入自己的 credentials 以后，会跳转到该页面询问用户是否确认授权？confirm or deny；
//            		 */
//            		.antMatchers("/", "/login", "/oauth/authorize", "/oauth/confirm_access").permitAll()
//            		
//            	.and()
//	            	.authorizeRequests()
//	            	.anyRequest().authenticated()
//	            	
//            	.and()
//		        	.formLogin()
//		    		.loginPage("/login");
//            
//        }
//    }
    
    /**
     * 
     * 注意，ResourceServerConfig 是对 API 的访问安全进行控制，既它的目的是对第三方 Client 的访问进行控制，所以，它只能通过 OAuth 的方式进行访问，也就是通过 Access Token；
     * 
     * 因为和 WebSecurity 一并使用，所以要使得对 Protected Resource 资源的访问的限制生效，必须设置 Order 的值，并且确保 ResourceServerConfig 所生成的 Filters 在 WebSecurityConfig 所生成的 Filters 之前执行； 
     * 
     * @author shangyang
     *
     */
	@Configuration
	@EnableResourceServer
	@Order(-10)
    static class ResourceServerConfig extends ResourceServerConfigurerAdapter{
	
        @Override
        public void configure(HttpSecurity http) throws Exception {
        	
            http.antMatcher("/api/**") // the filter chain defined for restful
                	.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
                	
                .and()
	                .authorizeRequests()
	                .antMatchers(HttpMethod.GET, "/api/user/{id}").access("hasRole('USER') and #oauth2.hasScope('read')")
	            
	            .and()
	            	.authorizeRequests().anyRequest().permitAll();
            		
        }
        
	}    
	
	/**
	 * 该资源是被保护的 Resource 资源；只有拿到 Access Token 以后，才能获取；
	 * 
	 * @param id
	 * @return
	 */
    @RequestMapping( value = "/api/user/{id}", method = RequestMethod.GET )
    public ResponseEntity<User> getUser(@PathVariable("id") long id){
    	
    	User user = new User();
    	
    	return new ResponseEntity<User>( user, HttpStatus.OK );
    	
    }

}
