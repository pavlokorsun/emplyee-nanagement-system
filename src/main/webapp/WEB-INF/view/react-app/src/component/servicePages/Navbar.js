import React, {Component} from 'react';
import {
    Collapse,
    DropdownItem,
    DropdownMenu,
    DropdownToggle,
    Nav,
    Navbar,
    NavbarBrand,
    NavbarToggler,
    NavItem,
    // NavLink,
    UncontrolledDropdown
} from 'reactstrap';
import {NavLink} from 'react-router-dom';

export default class AppNavbar extends Component {
    constructor(props) {
        super(props);
        this.state = {isOpen: false};
        this.toggle = this.toggle.bind(this);
    }

    toggle() {
        this.setState({
            isOpen: !this.state.isOpen
        });
    }

    render() {
        return (
            <Navbar color="light" light  expand="md" sticky={'top'}
                    className="shadow-sm py-0 border-dark border-bottom">
                <div>
                    <NavbarBrand to="/"><img
                        src={"https://res.cloudinary.com/go2it/image/upload/v1557970687/Go2IT_small.png"}/></NavbarBrand>
                    <NavbarToggler onClick={this.toggle}/>
                    <Collapse isOpen={this.state.isOpen} navbar>
                        <Nav className="ml-auto" navbar>
                            <NavItem>
                                <NavLink to="/employees" activeClassName="active">View all employees</NavLink>
                            </NavItem>
                            <NavItem>
                                <NavLink to="/contact"  activeClassName="active">Contact us</NavLink>
                            </NavItem>
                            <NavItem>
                                <NavLink
                                    href="https://www.facebook.com/Go2IT.ca" activeClassName="active">@Facebook</NavLink>
                            </NavItem>
                            <NavItem>
                                <NavLink
                                    href="https://github.com/ryzhman/employeeManagementSystem" activeClassName="active">GitHub</NavLink>
                            </NavItem>
                            <UncontrolledDropdown nav inNavbar>
                                <DropdownToggle nav caret>
                                    Profile
                                </DropdownToggle>
                                <DropdownMenu right>
                                    <DropdownItem>
                                        <NavLink to="/login">Login</NavLink>
                                    </DropdownItem>
                                    <DropdownItem>
                                        <NavLink to="/signUp">Create account</NavLink>
                                    </DropdownItem>
                                    <DropdownItem divider/>
                                    <DropdownItem>
                                        <NavLink href="/logout">Logout</NavLink>
                                    </DropdownItem>
                                </DropdownMenu>
                            </UncontrolledDropdown>
                        </Nav>
                    </Collapse>
                </div>
            </Navbar>
        );
    }
}