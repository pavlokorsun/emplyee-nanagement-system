package com.go2it.edu.emplyeenanagementsystem.service;

/**
 * @author Alex Ryzhkov
 */
public interface IEmployeeService {
	String getUserById(String employeeId);

	String getUsers();

	String createNewEmployee(String body);

	String updateEmployee(String employeeId);

	String deleteEmployee(String employeeId);

}
