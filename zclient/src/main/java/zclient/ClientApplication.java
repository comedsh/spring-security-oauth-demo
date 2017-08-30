package zclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ClientApplication {

	public static void main(String[] args) {
		
		SpringApplication.run(ClientApplication.class, args);
	}
	
    // 配置 URL 到 view 之间的映射
//    @Configuration
//    static class MvcConfig extends WebMvcConfigurerAdapter {
//        @Override
//        public void addViewControllers(ViewControllerRegistry registry) {
//            registry.addViewController("/").setViewName("index");
//        }
//    }
	
}