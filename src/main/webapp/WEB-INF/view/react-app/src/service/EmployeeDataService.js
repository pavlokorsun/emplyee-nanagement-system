import axios from 'axios';

class EmployeeDataService {
    fetchAllEmployees() {
        return axios.get(`/api/employees`)
            .then(res => res.data.employees)
            .catch(err => {
                console.log(err);
                return [{id: 'n/a'}];
            });
    }

}

export default EmployeeDataService;