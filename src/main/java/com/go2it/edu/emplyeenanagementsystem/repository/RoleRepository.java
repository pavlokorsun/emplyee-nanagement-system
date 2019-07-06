package com.go2it.edu.emplyeenanagementsystem.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.go2it.edu.emplyeenanagementsystem.entity.Role;
import com.go2it.edu.emplyeenanagementsystem.entity.RoleName;

/**
 * @author Alex Ryzhkov
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(RoleName roleName);
}
