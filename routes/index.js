const router = require("express").Router();

const User = require("../models/User.model");

const bcrypt = require("bcryptjs");
const saltRounds = 10;

const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedin = require("../middleware/isLoggedin");

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

// SIGNIN //
router.get("/signin", isLoggedOut, (req, res, next) => {
  res.render("users/signin")
});

router.post("/signin", isLoggedOut, (req, res, next) => {
  let {username, password} = req.body;

  if(username == "" || password == ""){
    res.render("users/signin", {mensajeError: "Missing fields"});
    return;
  }

  User
  .find({username})
  .then(result => {
    if(result.length != 0){
      res.render("users/signin", {mensajeError: "User already exists"});
      return;
    }

  })
  .catch(err => { next(err)});

  let salt = bcrypt.genSaltSync(saltRounds);
  let passwordEncriptado = bcrypt.hashSync(password, salt);

  User
  .create({
    username: username,
    password: passwordEncriptado,
  })
  .then(result => { res.redirect("/login") })
  .catch(err => { next(err) });
})


// LOGIN //
router.get("/login", isLoggedOut, (req, res, next) => {
  res.render("users/login");
});
router.post("/login", isLoggedOut, (req, res, next) => {
  let {username, password} = req.body;

  if(username == "" || password == "") {
    res.render("users/login", { mensajeError: "Missing fields" });
    return;
  }

  User
  .find({username})
  .then(result => {
    if(result.length == 0){
      res.render("users/login", {mensajeError: "Wrong fields"});
      return;
    }
    if(bcrypt.compareSync(password, result[0].password)) {
      req.session.currentUser = username; 
      res.redirect("/profile");
    } else {
      res.render("users/login", { mensajeError: "Missing fields" });
    }
  })
  .catch(err => { next(err)});
});


// PROFILE //

router.get("/profile", isLoggedin, (req, res, next) => {
  res.render("users/profile", {username: req.session.currentUser})
});

// LOG OUT //
router.get("/logout", isLoggedin, (req, res, next) => {
  req.session.destroy(err => {
    if(err) next(err);
    else res.redirect ("/login")
  })
})

// MAIN //
router.get("/main", isLoggedin, (req, res, next) => {
  res.render("users/main")
});

// PRIVATE //
router.get("/private", isLoggedin, (req, res, next) => {
  res.render("users/private")
})

module.exports = router;
