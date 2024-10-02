const express = require('express');
const bcrypt = require('bcryptjs');
const { User } = require('../index');  
const router = express.Router();

// Validate new user registration
function validateNewUser(req, res, next) {
  const { username, password } = req.body;
  const minLength = 8;
  const specialCharCount = 2;

  // Check for minimum length
  if (password.length < minLength) {
    return res.redirect('/register?error=Password must be at least ' + minLength + ' characters long');
  }

  // Check for special characters
  const specialChars = password.replace(/[a-zA-Z0-9]/g, '');
  if (specialChars.length < specialCharCount) {
    return res.redirect('/register?error=Password must contain at least ' + specialCharCount + ' special characters');
  }

  next();
}

// Registration route
router.post('/register', validateNewUser, async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.redirect('/register?error=Username already exists');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.redirect('/login'); 
  } catch (err) {
    next(err); 
  }
});

module.exports = router;
