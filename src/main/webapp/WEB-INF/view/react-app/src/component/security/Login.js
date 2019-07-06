import React, {Component} from 'react';
import AuthService from "../../service/AuthService";
import LoginForm from "../html/LoginForm";

const inputs = [{
    name: "userLogin",
    placeholder: "Enter your email address",
    type: "text"
}, {
    name: "password",
    placeholder: "Enter your password",
    type: "password"
}, {
    type: "submit",
    value: "Submit",
    className: "btn"
}];

const props = {
    name: 'loginForm',
    method: 'POST',
    action: '/api/auth',
    inputs: inputs
};

const params = new URLSearchParams(window.location.search);

class Login extends Component{
    constructor(props) {
        super(props);
        this.authService = AuthService;
    }

    render() {
        return (
            <LoginForm {...props} enctype='application/json'  />
        )
    }
}

export default Login;