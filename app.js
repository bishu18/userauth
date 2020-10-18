const express = require('express');
const app = express();
const { pool } = require("./db");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const cookieParser = require('cookie-parser')

app.use(express.json());
app.use(cookieParser());

//PORT
const port = process.env.PORT || 5000;

const initializePassport = require("./passport");

initializePassport(passport);

app.use(express.urlencoded({ extended: false }));

app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false
    })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render("index.ejs");
});

app.get('/users/signup', checkAuthenticated, (req, res) => {
    res.render("signup.ejs");
});

app.get('/users/update', checkAuthenticated, (req, res) => {
    res.render("update.ejs");
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render("login.ejs");
});


app.get("/users/profile", checkNotAuthenticated, (req, res) => {
    console.log(req.isAuthenticated());
    res.render("profile", { username: req.user.name, useremail: req.user.email });
});
  

app.get("/users/profile/:id", checkAuthenticated, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await pool.query("SELECT id, name, email FROM users WHERE id=$1", [id]);
         res.json(user.rows[0]);
    } catch (error) {
        console.log(error.message);
    }
});

app.get("/users/logout", (req, res) => {
    req.logout();
    res.render("index", { message: "You have logged out successfully" });
});
  

app.post("/users/signup", async (req, res) => {
    let { name, email, password } = req.body;
  
    let errors = [];
  
    if (!name || !email || !password) {
      errors.push({ message: "Please enter all fields" });
    }
  
    if (password.length < 6) {
      errors.push({ message: "Password must be a least 6 characters long" });
    }
  
    if (errors.length > 0) {
        res.render("signup", { errors });
    }else {
        hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);
    
        pool.query(
            `SELECT * FROM users
              WHERE email = $1`,
            [email],
            (err, results) => {
              if (err) {
                throw err;
              }
              if (results.rows.length > 0) {
                return res.render("register", {
                  message: "Email already registered"
                });
              } else {
                pool.query(
                  `INSERT INTO users (name, email, password)
                      VALUES ($1, $2, $3)
                      RETURNING id, password`,
                  [name, email, hashedPassword],
                  (err, results) => {
                    if (err) {
                      throw err;
                    }
                    req.flash("success_msg", "You are now registered. Please log in");
                    res.redirect("/users/login");
                  }
                );
              }
            }
        );

    }
});

app.post(
    "/users/login",
    passport.authenticate("local", {
      successRedirect: "/users/profile",
      failureRedirect: "/users/login",
      failureFlash: true
    })
);

app.put('/users/profile/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;
        const { email } = req.body;
        const { password } = req.body;
        hashedPassword = await bcrypt.hash(password, 10);
        const updateUser = await pool.query("UPDATE users SET name = $1, email = $2, password = $3 WHERE id= $4",
        [name, email, hashedPassword, id]
        );
        res.json("User updated");
    } catch (error) {
        console.log(error.message);
    }
});

app.delete('/users/profile/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const delUser = await pool.query("DELETE FROM users WHERE id=$1",[id]);
        res.json("user deleted");
    } catch (error) {
        console.log(error.message);
    }
});


function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/users/login");
    }
    next();
}
  
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
}

//Starting a Server
app.listen(port, () => {
    console.log(`Server started at ${port}`);
});