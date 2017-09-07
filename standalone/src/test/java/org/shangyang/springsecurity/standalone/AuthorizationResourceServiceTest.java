package org.shangyang.springsecurity.standalone;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 
 * @author shangyang
 *
 */
public class AuthorizationResourceServiceTest {
	
	private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	
	@Test
	public void testBCryptPasswordEncoder(){
		
		System.out.println( passwordEncoder.encode("password") );
		
		System.out.println( passwordEncoder.encode("secret") );
		
		
		
	}
	
}
