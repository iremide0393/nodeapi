const jwt = require('jsonwebtoken');
require('dotenv').config();
const expressjwt = require('express-jwt');
const User = require('../models/user');

exports.signup = async (req, res) => {
  const userExists = await User.findOne({ email: req.body.email });
  if (userExists)
    return res.status(403).json({
      error: 'Email already exist!'
    });
  const user = await new User(req.body);
  await user.save();
  res.status(200).json({ message: 'Signup successful! Please Login.' });
};

exports.signin = (req, res) => {
  //find the user base on email
  const { email, password } = req.body;
  User.findOne({ email }, (err, user) => {
    // if err or no user
    if (err || !user) {
      return res.status(401).json({
        error: 'User with that email does not exist. Please signup.'
      });
    }
    //if user is foun make sure the email and password match
    //create authenticate method in model and use here
    if (!user.authenticate(password)) {
      return res.status(401).json({
        error: 'Email and password do not match'
      });
    }

    //generate a token with user ID and secret
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    //persist the token as 't' in cookie with expiry date
    res.cookie('t', token, { expire: new Date() + 9999 });
    //return response with user and token with frontend client
    const { _id, name, email } = user;
    return res.json({ token, user: { _id, email, name } });
  });
};

exports.signout = (re, res) => {
  res.clearCookie('t');
  return res.json({ message: 'Signout success!' });
};

exports.requireSignin = expressjwt({
  //if the token is valid, express jwt appends the verified users id
  //in an auth key to the request object
  secret: process.env.JWT_SECRET,
  userProperty: 'auth'
});

exports.socialLogin = (req, res) => {
  // try signup by finding user with req.email
  let user = User.findOne({ email: req.body.email }, (err, user) => {
      if (err || !user) {
          // create a new user and login
          user = new User(req.body);
          req.profile = user;
          user.save();
          // generate a token with user id and secret
          const token = jwt.sign(
              { _id: user._id, iss: "NODEAPI" },
              process.env.JWT_SECRET
          );
          res.cookie("t", token, { expire: new Date() + 9999 });
          // return response with user and token to frontend client
          const { _id, name, email } = user;
          return res.json({ token, user: { _id, name, email } });
      } else {
          // update existing user with new social info and login
          req.profile = user;
          user = _.extend(user, req.body);
          user.updated = Date.now();
          user.save();
          // generate a token with user id and secret
          const token = jwt.sign(
              { _id: user._id, iss: "NODEAPI" },
              process.env.JWT_SECRET
          );
          res.cookie("t", token, { expire: new Date() + 9999 });
          // return response with user and token to frontend client
          const { _id, name, email } = user;
          return res.json({ token, user: { _id, name, email } });
      }
  });
};