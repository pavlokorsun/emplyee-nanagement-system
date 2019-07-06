package com.go2it.edu.emplyeenanagementsystem.controller;

import java.util.HashMap;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.go2it.edu.emplyeenanagementsystem.service.IEmployeeService;

/**
 * @author Alex Ryzhkov
 */
@RestController
@RequestMapping(value = "/api/employees")
public class EmployeeController {

	@Autowired
	private IEmployeeService employeeService;

	@RequestMapping(value = "/{id}", method = RequestMethod.GET)
	public ResponseEntity<JSONObject> getEmployeeById(@PathVariable(name = "id") String employeeId) {
		HashMap<String, String> hashMap = new HashMap<>();
		hashMap.put("status", "succesful");
		return new ResponseEntity<>(new JSONObject(hashMap), HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.GET)
	@ResponseBody
	public ResponseEntity<String> getEmployees() {
		return ResponseEntity.ok().body(employeeService.getUsers());
	}

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<JSONObject> createNewEmployee(@RequestBody String body) {
		HashMap<String, String> hashMap = new HashMap<>();
		hashMap.put("status", "succesful");
		return new ResponseEntity<>(new JSONObject(hashMap), HttpStatus.OK);
	}

	@RequestMapping(value = "/{id}", method = RequestMethod.PUT)
	public ResponseEntity<JSONObject> updateEmployee(@PathVariable(name = "id") String employeeId) {
		HashMap<String, String> hashMap = new HashMap<>();
		hashMap.put("status", "succesful");
		return new ResponseEntity<>(new JSONObject(hashMap), HttpStatus.OK);
	}

	@RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
	public ResponseEntity<JSONObject> deleteEmployee(@PathVariable(name = "id") String employeeId) {
		HashMap<String, String> hashMap = new HashMap<>();
		hashMap.put("status", "succesful");
		return new ResponseEntity<>(new JSONObject(hashMap), HttpStatus.OK);
	}
}
