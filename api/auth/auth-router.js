const router = require('express').Router()
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const { 
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength } = require('./auth-middleware')


//1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

router.post('/register', 
  checkUsernameFree, checkPasswordLength, 
  async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(
      password, // plain text
      8, // number of rounds of hashing 2 ^ 8
    )
    const newUser = { username, password: hash }
    const createdUser = await User.add(newUser)

    res.json(createdUser)
  } catch (err) {
    next(err)
  }
})


//2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const [user] = await User.findBy({ username })
    // does username correspont to an actual user?
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user
      // a cookie is set on client
      // a session is stored for that user
      res.json(`Welcome ${user.username}!`)
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err)
  }
})


//3 [GET] /api/auth/logout
router.get('/logout', async (req, res, next) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) res.json({ message: 'you cannot leave' })
      else res.json({ message: 'logged out' })
    })
  } else {
    res.json({
      message: 'no session'
    })
  }
})

module.exports = router
