package com.go2it.edu.emplyeenanagementsystem.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author Alex Ryzhkov
 */
@EnableWebMvc
@Configuration
public class MvcConfig implements WebMvcConfigurer {

	/**
	 * This method is used to map the resource being accessed from the client to the 'internal' version
	 *
	 * @param registry
	 */
	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {

		registry.addResourceHandler("/static/**")
				.addResourceLocations("/WEB-INF/view/react-app/build/static/");
		registry.addResourceHandler("/*.js").addResourceLocations("/WEB-INF/view/react-app/build/");
		registry.addResourceHandler("/*.json").addResourceLocations("/WEB-INF/view/react-app/build/");
		registry.addResourceHandler("/*.ico").addResourceLocations("/WEB-INF/view/react-app/build/");
		registry.addResourceHandler("/index.html", "/home.html", "/welcome.html", "/")
				.addResourceLocations("/WEB-INF/view/react-app/build/index.html");
	}
}
