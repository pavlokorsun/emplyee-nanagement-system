package com.go2it.edu.emplyeenanagementsystem.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.go2it.edu.emplyeenanagementsystem.config.security.CustomUserDetailsService;
import com.go2it.edu.emplyeenanagementsystem.config.security.JwtAuthenticationEntryPoint;
import com.go2it.edu.emplyeenanagementsystem.config.security.JwtAuthenticationFilter;

/**
 * @author Alex Ryzhkov
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		//each method in Controller can be verified against the user role
		securedEnabled = true, //using
		jsr250Enabled = true,
		prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired CustomUserDetailsService customUserDetailsService;

	@Autowired private JwtAuthenticationEntryPoint unauthorizedHandler;

	public SecurityConfig() {
		super();
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() {
		return new JwtAuthenticationFilter();
	}

	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(customUserDetailsService).passwordEncoder(encoder());
	}

	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
					.cors()
				.and()
					.csrf()
					.disable()
					.exceptionHandling()
					.authenticationEntryPoint(unauthorizedHandler)
				.and()
					.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
					.authorizeRequests()
					.antMatchers("/api/employees/**")
					.hasAnyRole("ADMIN", "USER")
					.antMatchers("/api/auth/**", "/api/auth")
					.permitAll()
					.antMatchers("/", "/home.html", "/index.html", "/welcome", "/contact", "/about")
					.permitAll()
					//MVC part - React pages
					.antMatchers(HttpMethod.GET, "/index*", "/static/**", "/*.js", "/*.json", "/*.ico")
					.permitAll()
					//All the rest of requests
					.anyRequest()
					.authenticated();

		http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

	}
}
