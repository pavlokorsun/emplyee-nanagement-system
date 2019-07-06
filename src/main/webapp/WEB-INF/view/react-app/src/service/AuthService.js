import decode from 'jwt-decode';
import axios from "axios/index";

class AuthService {

    isAuthenticated() {
        // Checks if there is a saved token and it's still valid
        const token = this.getToken();
        return !!token && !this.isTokenExpired(token);
    }

    isTokenExpired(token) {
        try {
            const decoded = decode(token);
            if (decoded.exp < Date.now() / 1000) { // Checking if token is expired. N
                return true;
            }
            else
                return false;
        } catch (err) {
            return false;
        }
    }

    setToken(idToken) {
        // Saves user token to localStorage
        localStorage.setItem('id_token', idToken);
        console.log(this.getProfile())
    }

    getToken() {
        // Retrieves the user token from localStorage
        return localStorage.getItem('id_token');
    }

    logout() {
        // Clear user token and profile data from localStorage
        localStorage.removeItem('id_token');
    }

    login(url, jsonWithDate) {
        //BE is mocked up for testing independently
        return true;

        //Integration testing
        // axios.post(url, jsonWithDate, {
        //     headers: {
        //         'content-type': 'application/json;charset=UTF-8'
        //     }
        // })
        // //successful response from the server side
        //     .then(response => {
        //         this.setToken(response.data.accessToken); // Setting the token in localStorage
        //         // return Promise.resolve(response);
        //         return true;
        //     })
        //     //something went wrong when the request was made
        //     .catch(e => {
        //         // console.warn(e);
        //         return false;
        //     })
    }

    getProfile() {
        // Using jwt-decode npm package to decode the token
        return decode(this.getToken());
    }

    sendRequest(url, data, options) {
        // performs api calls sending the required authentication headers
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        };

        // Setting Authorization header
        // Authorization: Bearer xxxxxxx.xxxxxxxx.xxxxxx
        if (this.isAuthenticated()) {
            headers['Authorization'] = 'Bearer ' + this.getToken()
        }

        //promise mock up for testing
        let promise = new Promise((resolve, reject) => {
                setTimeout(() => resolve({status:200, data : {'message':'Mock response'}}), 300);
            });
        promise.then((value) => value);
        return promise;

        //real-world BE call - to be used for integration testing
        // return axios({
        //     url: url,
        //     method: options.method,
        //     data: data
        // }, {
        //     headers,
        //     ...options
        // })
        //     .then(this._checkStatus)
        //     .then(response => response);
    }

    _checkStatus(response) {
        // raises an error in case response status is not a success
        if (response.status >= 200 && response.status < 300) { // Success status lies between 200 to 300
            return response
        } else {
            let error = new Error(response.statusText);
            error.response = response;
            throw error
        }
    }
}

export default new AuthService();