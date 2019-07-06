import React from 'react';

//Component that renders one particular line in Employees table
function Employee(props) {
    return (
        <tr key={props.employee.id}>
            <td>{props.employee.id}</td>
            <td>{props.employee.employee_name}</td>
            <td>{props.employee.employee_salary}</td>
            <td>{props.employee.employee_age}</td>
            <td>{props.employee.profile_image}</td>
            <td>{props.editButton}</td>
            <td>{props.deleteButton}</td>
        </tr>
    )
}

export default Employee;