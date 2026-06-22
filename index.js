const express = require('express');
const app = express();

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

require('dotenv').config();

// ======================
// MIDDLEWARE
// ======================

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ======================
// VIEW ENGINE
// ======================

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ======================
// USER SCHEMA
// ======================

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// ======================
// AUTH MIDDLEWARE
// ======================

function isLoggedIn(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.send('Invalid Token');
  }
}

// ======================
// ROUTES
// ======================

app.get('/home', (req, res) => {
  res.render("home");
});

// Register Page
app.get('/register', (req, res) => {
  res.render('register');
});

// Register User
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.send('User Already Exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashedPassword,
    });

    res.redirect('/login');
  } catch (err) {
    console.log(err);
    res.send('Something went wrong');
  }
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login');
});

// Login User
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.send('User Not Found');
    }

    const result = await bcrypt.compare(password, user.password);

    if (!result) {
      return res.send('Wrong Password');
    }

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
      },
      process.env.JWT_SECRET,
    );

    res.cookie('token', token, {
      httpOnly: true,
    });

    res.redirect('/profile');
  } catch (err) {
    console.log(err);
    res.send('Something went wrong');
  }
});

// Profile
app.get('/profile', isLoggedIn, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    res.render('profile', { user });
  } catch (err) {
    console.log(err);
    res.send('Something went wrong');
  }
});

app.get('/users', async (req, res) => {
  try {
    const users = await User.find();

    res.render('users', { users });
  } catch (err) {
    console.log(err);
    res.send('Something went wrong');
  }
});


// app.get("/profile/seen" , async(req, res)=>{

//   // let {username , email , password} = req.params;

//    try {
//      const user = await User.findById(req.user.id);

//      res.render('profile', { user });

//    } catch (err) {
//      console.log(err);
//      res.send('Something went wrong');
//    }
// })

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// ======================
// DATABASE CONNECTION
// ======================

mongoose
  .connect('mongodb://127.0.0.1:27017/authDemo')
  .then(() => {
    console.log('MongoDB Connected Successfully');

    app.listen(3000, () => {
      console.log('Server Running On Port 3000');
    });
  })
  .catch((err) => {
    console.log('MongoDB Connection Error');
    console.log(err);
  });

