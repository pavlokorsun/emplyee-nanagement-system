import React from 'react';
import {Redirect, Route} from "react-router-dom";


const ProtectedRoute = ({component: Component, authenticated, ...params}) => (
    <Route
        {...params}
        render={props =>
            authenticated ? (<Component {...params} {...props} />) : (<Redirect to={{
                        pathname: '/login',
                        state: {from: props.location}
                    }}
                />
            )
        }
    />
);

export default ProtectedRoute;