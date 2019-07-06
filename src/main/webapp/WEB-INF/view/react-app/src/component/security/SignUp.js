import React from "react";
import SignUpForm from "../html/SignUpForm";

const inputs = [{
    name: "name",
    placeholder: "Enter your name",
    type: "text"
},
    {
        name: "username",
        placeholder: "Enter your login id",
        type: "text"
    },
    {
        name: "email",
        placeholder: "Enter your email",
        type: "text"
    },
    {
        name: "password",
        placeholder: "Enter your password",
        type: "password"
    },
    {
        name: "password2",
        placeholder: "Repeat your password",
        type: "password"
    },
    {
        type: "submit",
        value: "Sign up",
        className: "btn"
    }];

const params = {
    name: 'signUpForm',
    method: 'POST',
    action: '/api/auth/user',
    inputs: inputs
};

function SignUp(props) {
    return <SignUpForm {...params} {...props}/>
}

export default SignUp;