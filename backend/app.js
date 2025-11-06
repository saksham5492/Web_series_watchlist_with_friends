const express = require('express');
const session = require('express-session');
const path = require('path');
const ejsMate = require('ejs-mate');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const wrapAsync = require('./utils/wrapAsync.js');
const ExpressError = require('./utils/expressError.js');
const nodemailer = require('nodemailer');
dotenv.config();

// ✅ Initialize app first
const app = express();

// ✅ Then configure session
app.use(session({
  secret: 'yourSecretKeyHere',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true only if using HTTPS
}));

// ✅ Now other app settings
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'watchlist',
  password: 'Tejaswi49!',
  multipleStatements: true 
});

connection.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Connected to MySQL database.');
  }
});

// ---------------------------------------------------------
// ROUTES
// ---------------------------------------------------------

// Root route
app.get('/', (req, res) => {
  res.send('Server running fine!');
});

// Login page
app.get('/watchlist/login', wrapAsync(async (req, res) => {
  const message = req.query.verified === 'success' ? '✅ Verification successful! Please log in.' : null;
  res.render('pages/login', { title: 'Login', message });
}));

// Register page
app.get('/watchlist/register', wrapAsync(async (req, res) => {
  res.render('pages/register', { title: 'Register' });
}));

// ---------------------------------------------------------
// REGISTER ROUTE WITH OTP
// ---------------------------------------------------------
app.post('/watchlist/register', wrapAsync(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).send('All fields are required.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  const q = `
    INSERT INTO user (name, email, password, verified, otp, otp_expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      otp = VALUES(otp),
      otp_expires_at = VALUES(otp_expires_at),
      verified = 0,
      password = VALUES(password)
  `;

  connection.query(q, [name, email, hashedPassword, 0, otp, otpExpiry], async (err) => {
    if (err) {
      console.error("Error inserting user:", err);
      return res.status(500).send("Registration failed.");
    }

    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL,
          pass: process.env.EMAIL_PASS
        }
      });

      await transporter.sendMail({
        from: process.env.EMAIL,
        to: email,
        subject: 'Your OTP for Email Verification',
        html: `<p>Hi ${name},</p>
               <p>Your OTP is: <b>${otp}</b></p>
               <p>This code will expire in 10 minutes.</p>`
      });

      console.log(`✅ OTP sent to ${email}`);
      res.redirect(`/verify-otp?email=${encodeURIComponent(email)}`);
    } catch (mailErr) {
      console.error("Email sending failed:", mailErr);
      res.status(500).send("Error sending OTP email.");
    }
  });
}));

// ---------------------------------------------------------
// LOGIN ROUTE
// ---------------------------------------------------------
app.post('/watchlist/login', wrapAsync(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('pages/login', {
      title: 'Login',
      message: '⚠️ Please fill in all fields.'
    });
  }

  const q = "SELECT * FROM user WHERE email = ?";
  connection.query(q, [email], async (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.render('pages/login', { title: 'Login', message: '⚠️ Server error. Try again later.' });
    }

    if (results.length === 0) {
      return res.render('pages/login', { title: 'Login', message: '❌ No account found with this email.' });
    }

    const user = results[0];

    if (!user.verified) {
      return res.render('pages/login', { title: 'Login', message: '⚠️ Please verify your email before logging in.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('pages/login', { title: 'Login', message: '❌ Incorrect password.' });
    }

    // ✅ Store user session
    req.session.user = { id: user.id, name: user.name, email: user.email };

    // ✅ Add login success message to session
    req.session.message = `🎉 Welcome back, ${user.name}!`;

    console.log(`✅ ${user.name} logged in successfully.`);
    res.redirect('/watchlist/home');
  });
}));

// ---------------------------------------------------------
// VERIFY OTP ROUTES
// ---------------------------------------------------------
app.get('/verify-otp', (req, res) => {
  const { email } = req.query;
  res.render('pages/verify-otp', { title: "Verify OTP", email });
});

app.post('/verify-otp', wrapAsync(async (req, res) => {
  const { email, otp } = req.body;

  const q = "SELECT * FROM user WHERE email = ? AND otp = ?";
  connection.query(q, [email, otp], (err, results) => {
    if (err) return res.status(500).send("Server error");
    if (results.length === 0) return res.status(400).send("Invalid OTP");

    const user = results[0];
    const now = new Date();

    if (new Date(user.otp_expires_at) < now) {
      return res.status(400).send("OTP expired. Please register again.");
    }

    const updateQ = "UPDATE user SET verified = 1, otp = NULL, otp_expires_at = NULL WHERE email = ?";
    connection.query(updateQ, [email], (err2) => {
      if (err2) return res.status(500).send("Error updating user status");
      res.redirect('/watchlist/login?verified=success');
    });
  });
}));



// ✅ Make logged-in user available in all EJS templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});




// ---------------------------------------------------------
// HOME PAGE
// ---------------------------------------------------------
app.get('/watchlist/home', wrapAsync(async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/watchlist/login');
  }

  const q = `
    SELECT s.series_id, s.title, s.release_year, s.summary, s.platform, 
           s.poster_url, s.series_rating, g.genre_id, g.genre_name
    FROM series s 
    JOIN series_genres sg ON s.series_id = sg.series_id 
    JOIN genres g ON sg.genre_id = g.genre_id 
    ORDER BY s.series_id, g.genre_name;
  `;

  connection.query(q, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Internal Server Error");
    }

    // ✅ Get message from session if any
    const message = req.session.message || null;
    req.session.message = null; // clear it after showing once

    // res.render("pages/home.ejs", { results, message });
    res.render("pages/home.ejs", { results, user: req.session.user, message: null });


  });
}));

// ---------------------------------------------------------
// ERROR HANDLING
// ---------------------------------------------------------
app.all('/', (req, res, next) => {
  next(new ExpressError('Page Not Found', 404));
});

app.use((err, req, res, next) => {
  const { statusCode = 500, message = 'Something went wrong' } = err;
  res.status(statusCode).send(message);
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.redirect('/watchlist/home');
    }
    res.clearCookie('connect.sid');
    res.redirect('/watchlist/login');
  });
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
app.listen(3000, () => {
  console.log('🚀 Server running at http://localhost:3000');
});
