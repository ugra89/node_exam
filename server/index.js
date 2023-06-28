const express = require('express');
const mysql = require('mysql2');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const { authenticate } = require('./middleware');

require('dotenv').config();

const server = express();
server.use(express.json());
server.use(cors());

const mysqlConfig = {
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASS,
  database: 'bill',
};

const dbPool = mysql.createPool(mysqlConfig).promise();

dbPool.getConnection((err) => {
  if (err) throw err;
  console.log('connected to db');
});

const userSchema = Joi.object({
  full_name: Joi.string().required(),
  email: Joi.string().email().trim().lowercase().required(),
  password: Joi.string().required(),
});

server.get('/', authenticate, (req, res) => {
  console.log(req.user);
  res.status(200).send({ message: 'Authorized' });
});

server.post('/register', async (req, res) => {
  let payload = req.body;

  try {
    payload = await userSchema.validateAsync(payload);
  } catch (err) {
    console.error(err);

    return res.status(400).send({ error: 'All fields are required' });
  }

  try {
    const encryptedPassword = await bcrypt.hash(payload.password, 10);
    await dbPool.execute(
      `
              INSERT INTO users (full_name, email, password)
              VALUES (?, ?, ?)
          `,
      [payload.full_name, payload.email, encryptedPassword]
    );

    return res.status(201).end();
  } catch (err) {
    console.error(err);
    return res.status(500).end();
  }
});

server.post('/login', async (req, res) => {
  let payload = req.body;

  try {
    payload = await userSchema.validateAsync(payload);
  } catch (err) {
    console.error(err);

    return res.status(400).send({ error: 'All fields are required' });
  }

  try {
    const [data] = await dbPool.execute(
      `
          SELECT * FROM users
          WHERE email = ?
      `,
      [payload.email]
    );

    if (!data.length) {
      return res.status(400).send({ error: 'Email or password did not match' });
    }

    const isPasswordMatching = await bcrypt.compare(
      payload.password,
      data[0].password
    );

    if (isPasswordMatching) {
      const token = jwt.sign(
        {
          email: data[0].email,
          id: data[0].id,
        },
        process.env.JWT_SECRET
      );
      return res.status(200).send({ token });
    }

    return res.status(400).send({ error: 'Email or password did not match' });
  } catch (err) {
    console.error(err);
    return res.status(500).end();
  }
});
server.post('/groups', authenticate, (req, res) => {
  console.log(req.user);
  res.status(200).send({ message: 'Authorized' });
});
// tik prisijungusius vartotojus i /groups ileidzia

server.get('/groups', (req, res) => {
  //code here
});

server.post('/accounts', (req, res) => {
  //code here
});

server.get('/accounts', (req, res) => {
  //code here
});

server.get('/bills/:group_id', (req, res) => {
  //code here
});
server.post('/bills', (req, res) => {
  //code here
});

server.listen(process.env.PORT, () =>
  console.log(`Server is listening to ${process.env.PORT} port`)
);
