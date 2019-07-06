package com.go2it.edu.emplyeenanagementsystem.config.security;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.go2it.edu.emplyeenanagementsystem.entity.User;
import com.go2it.edu.emplyeenanagementsystem.repository.UserRepository;

/**
 * @author Alex Ryzhkov
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired private UserRepository userRepository;

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email)
			throws UsernameNotFoundException {
		// Let people login with either username or email
		User user = userRepository.findByEmail(email)
				.orElseThrow(() ->
						new UsernameNotFoundException("User not found with username or email : " + email)
				);

		return UserPrincipal.create(user);
	}

	// This method is used by JWTAuthenticationFilter
	@Transactional
	public UserDetails loadUserById(Long id) {
		User user = userRepository.findById(id).orElseThrow(
				() -> new UsernameNotFoundException("User not found with id : " + id)
		);

		return UserPrincipal.create(user);
	}
}