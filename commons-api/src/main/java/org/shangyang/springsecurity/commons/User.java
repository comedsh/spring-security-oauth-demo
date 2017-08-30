package org.shangyang.springsecurity.commons;

/**
 * just a demo
 *  
 * @author shangyang
 *
 */
public class User{
	
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
	
	public String toString(){
		
		return "username: " + username +"; hobbies: " + hobbies;
	}
	
}