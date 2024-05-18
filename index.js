const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const jwksClient = require('jwks-rsa');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'authorization';
const client_id = 'HmyoofaoL8mhp3gyBHGdMqlQANiqpc0s';
const client_secret = 'jTfD9KYUxiW35bl6Nm6RC0Njx3gHrDYAJtIwIrrXsIZEO5depFk4oFeuLGfp6usI';
const audience = 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/api/v2/';

app.use(async (req, res, next) => {
    const token = req.headers[SESSION_KEY];

    if (token?.length) {
        var client = jwksClient({
            jwksUri: 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/.well-known/jwks.json'
        });

        function getKey(header, callback) {
            client.getSigningKey(header.kid, function (err, key) {
                var signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
            });
        }

        try {
            jwt.verify(token, getKey, function (err, decoded) {
                if (err) {
                    console.error(err);
                    return next();
                }
                req.session = decoded;
                console.log('Token:', token); // Виведення токена в консоль
                next();
            });
        } catch (e) {
            console.log(e);
            next();
        }
    } else {
        next();
    }
});

app.get('/', (req, res) => {
    if (req.session?.sub) {
        return res.json({
            username: req.session.sub,
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname, '/index.html'));
});

app.get('/logout', (req, res) => {
    res.redirect('/');
});

const loginUser = async (login, password) => {
    const getToken = {
        method: 'post',
        url: 'https://dev-iok04fd4rdabjfsd.eu.auth0.com/oauth/token',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: {
            grant_type: 'password',
            username: login,
            password: password,
            audience: audience,
            scope: 'offline_access',
            client_id: client_id,
            client_secret: client_secret
        }
    };

    try {
        const response = await axios.request(getToken);
        if (response.status === 200) {
            console.log('Token:', response.data.access_token); // Виведення токена в консоль
            return { token: response.data.access_token };
        } else {
            return { error: 'Login failed' };
        }
    } catch (error) {
        console.error('Error occurred during login:', error);
        return { error: 'Login failed' };
    }
};

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    try {
        const loginResponse = await loginUser(login, password);
        if (loginResponse.token) {
            res.status(200).json({ token: loginResponse.token });
        } else {
            res.status(401).json({ error: 'Login failed' });
        }
    } catch (error) {
        console.error('Error occurred:', error);
        res.status(401).json({ error: 'Login failed' });
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const connection = 'Username-Password-Authentication';
        const grant_type = 'client_credentials';

        const token = await axios.post('https://dev-iok04fd4rdabjfsd.eu.auth0.com/oauth/token', {
            client_id,
            client_secret,
            audience,
            grant_type
        });

        const response = await axios.post('https://dev-iok04fd4rdabjfsd.eu.auth0.com/api/v2/users', {
            email,
            connection,
            password
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token.data.access_token
            }
        });

        if (response.status === 201) {
            const loginResponse = await loginUser(email, password);
            if (loginResponse.token) {
                res.status(200).json({ token: loginResponse.token });
            } else {
                res.status(401).json({ error: 'Login failed' });
            }
        } else {
            res.status(200).json(response.data);
        }
    } catch (error) {
        console.error('Error occurred:', error.response.data);
        res.status(error.response.status || 500).json({ error: 'An error occurred' });
    }
});

app.listen(3000, () => {
    console.log('Example app listening on port 3000');
});