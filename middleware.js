module.exports.isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/home');
};

module.exports.isDoctor = (req, res, next) => {
  if (req.user && req.user.constructor.modelName === 'Doctor') return next();
  res.redirect('/home');
};

module.exports.isPatient = (req, res, next) => {
  if (req.user && req.user.constructor.modelName === 'Patient') return next();
  res.redirect('/home');
};
