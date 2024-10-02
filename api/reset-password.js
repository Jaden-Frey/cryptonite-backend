const express = require('express');
const bcrypt = require('bcryptjs');
const { User } = require('../index');  
const router = express.Router();

// Validate new password strength
function validateNewPassword(req, res, next) {
  const { newPassword } = req.body;
  const minLength = 8;
  const specialCharCount = 2;

  // Check for minimum length
  if (newPassword.length < minLength) {
    return res.redirect('/reset-password?error=Password must be at least ' + minLength + ' characters long');
  }

  // Check for special characters
  const specialChars = newPassword.replace(/[a-zA-Z0-9]/g, '');
  if (specialChars.length < specialCharCount) {
    return res.redirect('/reset-password?error=Password must contain at least ' + specialCharCount + ' special characters');
  }

  next();
}

// Reset password route
router.post('/reset-password', validateNewPassword, async (req, res, next) => {
  const { username, newPassword } = req.body;

  try {
    // Find the user by username
    const user = await User.findOne({ username });

    // If user doesn't exist
    if (!user) {
      return res.redirect('/reset-password?error=Invalid Username Entered');
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    // Redirect the user back to the login page
    res.redirect('/login');
  } catch (err) {
    next(err); 
  }
});

module.exports = router;
