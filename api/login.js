const express = require('express');
const passport = require('passport');
const router = express.Router();

// Login route
router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.redirect('/login?error=' + info.message);
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect('/'); 
    });
  })(req, res, next);
});

module.exports = router;
