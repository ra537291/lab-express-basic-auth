module.exports = (req, res, next) => {
    if(req.session.currentUser) res.redirect("/profile");
    else next();
  }