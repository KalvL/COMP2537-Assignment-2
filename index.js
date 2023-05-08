require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3001;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

const url = require('url');
const navLinks = [
  {name: "Home", link: "/"},
  {name: "Admin", link: "/admin"},
  {name: "Members", link: "/members"},
  {name: "404", link: "/404"},
  {name: "Log out", link: "/logout"}
]

app.use("/", (req,res,next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentURL = url.parse(req.url).pathname;
  next();
});

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
})

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: true
}
));

// Check if session is valid
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

// Validate session
function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    res.redirect('/login');
  }
}

// Check for admin authorization
function isAdmin(req) {
  if (req.session.user_type == 'admin') {
    return true;
  }
  return false;
}

// 403 Page
function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", { error: "403 - Not Authorized" });
    return;
  }
  else {
    next();
  }
}

// NoSQL injection attack validation
app.get('/nosql-injection', async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();
  console.log(result);
  res.send(`<h1>Hello ${username}</h1>`);
});

// Sign up validation
app.post('/submitUser', async (req, res) => {
  var username = req.body.name;
  var email = req.body.email;
  var password = req.body.password;
  var user_type = "user";
  // var html = "";
  let missingField = false;

  if (username && email && password) {
    const schema = Joi.object(
      {
        username: Joi.string().max(20).required(),
        email: Joi.string().required(),
        password: Joi.string().max(20).required(),
        user_type: Joi.string().required()
      });

    const validationResult = schema.validate({ username, email, password, user_type });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: user_type });
    console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');
    return;
  } else {
    res.render("submitUser", {username: username, email: email, password: password, missingField: missingField});
    return;
  }
});

// Login Validation
app.post('/loginSubmit', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(50).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, user_type: 1, _id: 1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("email not found");
    res.render("loginSubmit");
    return
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
  }
  else {
    console.log("incorrect password");
    res.render("loginSubmit");
    return;
  }
});

// Sign up page
app.get('/signup', (req, res) => {
  res.render("signup");
});

// Login page
app.get('/login', (req, res) => {
  res.render("login", { navLinks: navLinks });
});

// Logout and destroy session
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Homepage
app.get('/', (req, res) => {
  username = req.session.username;
  if (!req.session.authenticated) {
    res.render("index");
  } else {
    res.render("index-authorized", { username: username });
  }
});

// Admin Page
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection.find().project({ username: 1, user_type: 1, _id: 1 }).toArray();
  res.render("admin", { users: result });
});

// Promote user to admin 
app.get('/promote', async (req,res) => {
  let username = req.query.promote;
  const filter = { username: username };
  const updateDocument = {
    $set: {
      user_type: 'admin',
    },
  };
  await userCollection.updateOne(filter, updateDocument);
  res.redirect('/admin');
});

// Demote admin to user 
app.get('/demote', async (req, res) => {
  let username = req.query.demote;
  const filter = { username: username };
  const updateDocument = {
    $set: {
      user_type: 'user',
    },
  };
  await userCollection.updateOne(filter, updateDocument);
  res.redirect('/admin');
});

// Members Page
app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return
  }
  res.render("members", {username: req.session.username });
});

app.use(express.static(__dirname + "/public"));

// 404 Page
app.get("/does_not_exist", (req, res) => {
  res.status(404);
  res.render("404");
});

// Redirect to 404 Page
app.get("*", (req, res) => {
  res.redirect('/does_not_exist');
})

app.listen(port, () => {
  console.log("Node application listening on port " + port);
}); 