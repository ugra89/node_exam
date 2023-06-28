const jwt = require('jsonwebtoken');

module.exports = {
  authenticate: (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      const user = jwt.verify(token, process.env.JWT_SECRET);
      req.user = user;
      next();
    } catch (err) {
      console.error(err);

      res.status(401).send({ error: 'Token is bad' });
    }
  },
};
