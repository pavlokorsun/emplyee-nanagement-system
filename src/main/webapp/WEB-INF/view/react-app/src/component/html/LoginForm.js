import React, {Component} from 'react';
import PropTypes from 'prop-types';
import Input from './Input';
import AuthService from '../../service/AuthService';

class LoginForm extends Component {

    constructor(props) {
        super(props);
        this.authService = AuthService;

        if (props.error) {
            this.state = {
                failure: 'wrong username or password!',
                errcount: 0
            };
        } else {
            this.state = {errcount: 0};
        }
    }

    handleError = (field, errmsg) => {
        if (!field) {
            return;
        }

        if (errmsg) {
            this.setState((prevState) => ({
                failure: '',
                errcount: prevState.errcount + 1,
                errmsgs: {...prevState.errmsgs, [field]: errmsg}
            }))
        } else {
            this.setState((prevState) => ({
                failure: '',
                errcount: prevState.errcount === 1 ? 0 : prevState.errcount - 1,
                errmsgs: {...prevState.errmsgs, [field]: ''}
            }))
        }
    };

    renderError = () => {
        if (this.state.errcount || this.state.failure) {
            const errmsg = this.state.failure
                || Object.values(this.state.errmsgs).find(v => v);
            return <div className="error">{errmsg}</div>
        }
    };

    convertFormToJSON = () => {
        let resultJSON = {};

        this.props.inputs.forEach((input, React) => {
            let inputName = input.name;
            if (this.refs[inputName]) {
                resultJSON[inputName] = this.refs[inputName].state.value;
            }
        });
        return resultJSON;
    };

    handleSubmit = (event) => {
        //event.preventDefault();

        let result = this.authService.login(this.form.action, this.convertFormToJSON());
        if (result) {
            //this.props.history.push('/');
            this.props.history.replace('/');
        } else {
            console.log("User login failed");
        }

    };

    render() {
        const inputs = this.props.inputs.map(
            ({name, placeholder, type, value, className}, index) => (
                <Input key={index} name={name} placeholder={placeholder} type={type} value={value}
                       className={type === 'submit' ? className : ''} ref={name} handleError={this.handleError} />
            )
        );
        const errors = this.renderError();
        return (
            <form {...this.props} onSubmit={this.handleSubmit} ref={fm => {
                this.form = fm
            }}>
                {inputs}
                {errors}
            </form>
        )
    }
}

LoginForm.propTypes = {
    name: PropTypes.string,
    action: PropTypes.string,
    method: PropTypes.string,
    inputs: PropTypes.array,
    error: PropTypes.string
};

export default LoginForm;