const bcrypt = require('bcryptjs')
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model')
const jwt = require('jsonwebtoken')
const { jwtSecret } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const { role_name } = req
    const rounds = process.env.BCRYPT_ROUNDS || 8
    const hash = bcrypt.hashSync(password, rounds)
    const newUser = {
      username: username,
      password: hash,
      role_name: role_name
    }

    const dbUser = await Users.add(newUser)
    res.status(201).json({dbUser})
  } catch (err) {
    next(err)
  }
  
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = buildToken(req.user)
    res.json({
      message: `${req.user.username} is back!`,
      token
    })
  } else {
    next({
      status: 401,
      message: 'Invalid credentials'
    })
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, jwtSecret, options)
}

module.exports = router;
