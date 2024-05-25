var express = require('express');
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});

/* POST User register. */
router.post('/register', function (req, res, next) {
  const { email, username, password } = req.body;
  if (!email || !username || !password) {
    return res.status(400).send("Request body incomplete - Please enter all fields");
  }

  const queryUsers = req.db.from("users").select("*").where("email", "=", email);
  queryUsers.then(users => {
    if (users.length > 0) {
      res.status(400).json({
        error: true,
        msg: "User already exists"
      });
      return
    }
    const saltRounds = 10;
    const hash = bcrypt.hashSync(password, saltRounds);
    const user = { email, username, hash };
    return req.db("users").insert(user);
  }).then(() => {
    res.status(201).json({ error: true, msg: "User registered" });
  })
});

/* POST User login. */
router.post('/login', function (req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Request body incomplete - Please enter all fields");
  }
  const queryUsers = req.db
    .from("users")
    .select("email", "hash")
    .where("email", "=", email)
    .then((users) => {
      if (users.length === 0) {
        res.status(401).json({
          error: true,
          msg: "User does not exist"
        });
        const user = users[0];
        return bcrypt.compare(password, user.hash);
      }
      const user = users[0];
      return bcrypt.compare(password, user.hash);
    }).then(match => {
      if (!match) {
        res.status(401).json({
          error: true,
          msg: "Password incorrect"
        });
      }
      const secretKey = "secret";
      const expires_in = 60 * 60 * 24;

      const exp = Date.now() + expires_in * 1000;
      const token = jwt.sign({ email, exp }, secretKey);

      res.json({ token_type: "Bearer", token, expires_in })

    })
});


const authorize = (req, res, next) => {
  const authorization = req.headers.authorization;
  let token = null;

  if (authorization && authorization.split(" ").length === 2) {
    token = authorization.split(" ")[1];
    console.log("Token: ", token)
  } else {
    return res.status(403).send("Unauthorized");
  }
  try {
    const secretKey = "secret";
    const decoded = jwt.verify(token, secretKey);
    if (decoded.exp < Date.now()) {
      return res.status(403).send("Token has expired");
    }
    req.email = decoded.email;
    next();
  } catch (err) {
    res.json({ error: true, msg: "Token is not valid: ", err });
  }

  next();
}

router.post("/task", authorize, (req, res) => {
  res.json({ doSomething: req.email });
});
module.exports = router;
