const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const expressSession = require('express-session');
const PGSession = require('connect-pg-simple')(expressSession);
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const client = require('./db');

dotenv.config();

const port = process.env.SERVER_PORT;

// initialize express.js
const app = express();

// function to set the header
function setContentType(contentType) {
  return (req, res, next) => {
    res.setHeader('Content-Type', contentType);
    next();
  };
}

// set body parser to destructuring object
app.use(bodyParser.json());

// set the header content type to application/json
app.use(setContentType('application/json'));

// set the session
app.use(
  expressSession({
    store: new PGSession({
      pool: client,
      table: 'user_session',
      createTableIfMissing: true,
    }),
    secret: 'my_token',
    resave: false,
    saveUninitialized: false,
  }),
);

app.post('/register', async (req, res) => {
  const { name, username, password } = req.body;

  try {
    const id = nanoid(20);
    const createdAt = new Date().toISOString();
    const updatedAt = createdAt;

    // name validation
    if (!name) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Please insert your name',
      });
    }
    // username validation
    if (!username) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Please insert your username',
      });
    }
    // password validation
    if (!password) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Please insert your password',
      });
    }
    // query to get user in database
    const isSuccess = await client.query(
      'SELECT * FROM users WHERE username = $1',
      [username],
    );
    // checking if user already exist in database
    if (isSuccess.rowCount > 0) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Username already exists',
      });
    }
    // hashing the password with auto-generated salt
    const hash = await bcrypt.hash(password, 10);
    // query insert for inserting data into database
    await client.query(
      'INSERT INTO users(id_user,name_user, username, password_user,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, name, username, hash, createdAt, updatedAt],
    );
    // return message and data if query successfully executed
    return res.status(201).send({
      status: 'success',
      message: 'User registered successfully',
      data: {
        user: name,
      },
    });
  } catch (err) {
    return res.status(500).send({
      status: 'fail',
      message: 'Registration Failed',
      error: err.message,
    });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // username validation
    if (!username) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Please insert your username',
      });
    }
    // password validation
    if (!password) {
      return res.status(400).send({
        status: 'fail',
        message: 'Registration failed. Please insert your password',
      });
    }
    // query to get user in database
    const query = await client.query(
      'SELECT * FROM users WHERE username = $1',
      [username],
    );
    // user data from database
    const result = query.rows[0];
    // checking if user not found in database
    if (!result) {
      return res.status(400).send({
        status: 'fail',
        message: 'User not found',
      });
    }
    // checking the password hashing from database
    const checkPass = await bcrypt.compare(password, result.password_user);
    if (!checkPass) {
      return res.status(400).send({
        status: 'fail',
        message: 'Login Failed. Please insert correct username and password',
      });
    }
    // generating token using jsonwebtoken with 1 hour expiration
    const token = jwt.sign({ id: result.id }, 'my_token', { expiresIn: '1h' });
    // set user data as session user
    req.session.user = result;
    // returning message if login successful
    return res.status(200).send({
      status: 'success',
      message: 'Login Success',
      data: {
        token,
      },
    });
  } catch (err) {
    return res.status(500).send({
      status: 'fail',
      message: err.message,
    });
  }
});

app.get('/dashboard', (req, res) => {
  try {
    // getting token from request header
    const bearer = req.headers.authorization;
    // splitting the token
    const token = bearer.split(' ')[1];
    // checking if token doesn't exist
    if (!token) {
      return res.status(403).send({
        status: 'unauthorized',
        message: 'No Token Provided',
      });
    }
    // validating the token using jsonwebtoken
    const tokenValidation = jwt.verify(token, 'my_token');
    // checking the token validity
    if (!tokenValidation) {
      return res.status(403).send({
        status: 'unauthorized',
        message: 'Invalid token',
      });
    }
    // returning the message if token successfully validated
    return res.status(200).send({
      status: 'success',
      message: 'This is dashboard page',
    });
  } catch (err) {
    return res.status(500).send({
      status: 'fail',
      message: err.message,
    });
  }
});

app.post('/logout', (req, res) => {
  // destroying/deleting session from database
  req.session.destroy((err) => {
    if (err) throw err;
    // returning message
    return res.status(201).send({
      status: 'success',
      message: 'Logout success',
    });
  });
});

// just a routing test
app.get('/', (req, res) => {
  res.status(200).send({
    status: 'success',
    message: 'Welcome to ExpressJS',
  });
});

// start the server in local with port 3000
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
