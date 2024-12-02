app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/login', // Redirect to login on failure
}), (req, res) => {
  // Successful login, send token and user data to frontend
  const user = req.user;
  const token = user.token; // Assuming token is stored after successful login
  const email = user.profile.emails[0].value;

  // Render the page and send token and email to the frontend
  res.render('welcome', {
    success: true,
    token: token,
    userEmail: email
  });
});
