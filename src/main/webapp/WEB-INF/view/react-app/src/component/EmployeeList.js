import React, {Component} from 'react';
import Employee from './Employee';
import EmployeeDataService from '../service/EmployeeDataService';

const employeeDataService = new EmployeeDataService();

class EmployeeList extends Component {
    constructor(props) {
        super(props);
        this.state = {
            isLoading: true,
            employees: []
        };
        this.getEmployeeList = this.getEmployeeList.bind(this);
    }

    componentDidMount() {
        this.setState({isLoading: true});

        this.getEmployeeList();
    }

    getEmployeeList() {
        this.setState({isLoading: true});

        employeeDataService.fetchAllEmployees()
            .then(employees => this.setState({employees: JSON.parse(employees), isLoading: false}));
    }

    render() {
        return (
            <div className="container">
                <h3>All Employees</h3>
                <div className="container">
                    <table className="table">
                        <thead>
                        <tr>
                            <th>Id</th>
                            <th>Name</th>
                            <th>Salary</th>
                            <th>Age</th>
                            <th>Profile Image</th>
                            <th></th>
                            <th></th>
                        </tr>
                        </thead>
                        <tbody>
                        {
                            this.state.employees.map(
                                employee =>
                                    <Employee employee={employee}/>
                            )
                        }
                        </tbody>
                    </table>
                </div>
            </div>
        )
    }
}

export default EmployeeList;