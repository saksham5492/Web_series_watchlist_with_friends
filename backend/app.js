const mysql = require('mysql2');
const express = require('express');
const path = require('path');
const ejsMate = require('ejs-mate');
const wrapAsync = require('./utils/wrapAsync.js');
const ExpressError = require('./utils/expressError.js');
const { v4: uuidv4 } = require('uuid');
const { resourceLimits } = require('worker_threads');

const app = express();

// Set up EJS-Mate and view engine
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs'); 
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'watchlist',
  password: 'Tejaswi49!'
});

// Routes
app.get('/', (req, res) => {
  res.send('Server running fine!');
});

app.get('/watchlist/login', wrapAsync(async (req, res) => {
  res.render("pages/login", { title: "Login" });
}));

app.get('/watchlist/register', wrapAsync(async (req, res) => {
  res.render("pages/register", { title: "Register" });
}));


app.get('/watchlist/home', wrapAsync(async (req, res) => {
  const q = "SELECT * FROM Series";

  connection.query(q, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Internal Server Error");
    }

    res.render("pages/home.ejs", {results});
  });
}));

// Error handling
app.all('/', (req, res, next) => {
  next(new ExpressError('Page Not Found', 404));
});

app.use((err, req, res, next) => {
  const { statusCode = 500, message = 'Something went wrong' } = err;
  res.status(statusCode).send(message);
});

// Start server
app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
