var express = require('express');
var router = express.Router();
const bcrypt = require("bcrypt");
const crypto = require('crypto');
const jwt = require("jsonwebtoken");

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});

const generateSecretKey = () => {
  return crypto.randomBytes(32).toString('hex');
};
const secretKey = generateSecretKey();

/* POST User register. */
router.post('/register', async function (req, res, next) {
  const { email, username, password } = req.body;
  if (!email || !username || !password) {
    return res.status(400).send("Request body incomplete - Please enter all fields");
  }

  try {
    const users = await req.db.from("users").select("*").where("email", "=", email);
    if (users.length > 0) {
      return res.status(400).json({
        error: true,
        msg: "User already exists"
      });
    }
    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);
    const user = { email, username, hash };
    await req.db("users").insert(user);

    // Generate JWT token on successful registration
    const expires_in = 60 * 60 * 24; // Set expiry time (e.g., 24 hours)
    const exp = Math.floor(Date.now() / 1000) + expires_in;
    const token = jwt.sign({ email: user.email, exp }, secretKey);

    res.status(201).json({ error: false, msg: "User registered successfully", username, token });
  } catch (err) {
    next(err);
  }
});

/* POST User login. */
router.post('/login', async function (req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Request body incomplete - Please enter all fields");
  }

  try {
    const users = await req.db.from("users").select("email", "hash").where("email", "=", email);
    if (users.length === 0) {
      return res.status(401).json({
        error: true,
        msg: "User does not exist"
      });
    }
    const user = users[0];
    const match = await bcrypt.compare(password, user.hash);
    if (!match) {
      return res.status(401).json({
        error: true,
        msg: "Password incorrect"
      });
    }
    const expires_in = 60 * 60 * 24;
    const exp = Math.floor(Date.now() / 1000) + expires_in;
    const token = jwt.sign({ email: user.email, exp }, secretKey);

    const userResults = await req.db.from('users').select("email", "username").where("email", "=", user.email);
    if (userResults.length === 0) {
      return res.status(500).json({ error: true, msg: "Internal server error" });
    }
    const loggedInUser = userResults[0];
    res.json({ token_type: "Bearer", token, expires_in, username: loggedInUser.username });
  } catch (err) {
    next(err);
  }
});

/* Middleware to authorize user */
const authorize = (req, res, next) => {
  const authorization = req.headers.authorization;
  let token = null;

  if (authorization && authorization.split(" ").length === 2) {
    token = authorization.split(" ")[1];
  } else {
    return res.status(403).send("Unauthorized");
  }
  try {
    const decoded = jwt.verify(token, secretKey);
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return res.status(403).send("Token has expired");
    }
    req.email = decoded.email;
    next();
  } catch (err) {
    res.status(403).json({ error: true, msg: "Token is not valid", err });
  }
};

// GET all tasks
router.get('/tasks', authorize, async (req, res, next) => {
  try {
    const tasks = await req.db.from('Tasks').select("*").where("userId", "=", req.email);
    res.json(tasks);
  } catch (err) {
    next(err);
  }
});

// GET all todo tasks
router.get('/tasks/todo', authorize, async (req, res, next) => {
  try {
    const tasks = await req.db.from('Tasks').select("*").where("userId", "=", req.email).andWhere("completed", "=", 0);
    res.json(tasks);
  } catch (err) {
    next(err);
  }
});

// GET all completed tasks
router.get('/tasks/completed', authorize, async (req, res, next) => {
  try {
    const tasks = await req.db.from('Tasks').select("*").where("userId", "=", req.email).andWhere("completed", "=", 1);
    res.json(tasks);
  } catch (err) {
    next(err);
  }
});

// GET tasks by date
router.get('/tasks/date/:date', authorize, async (req, res, next) => {
  try {
    const { date } = req.params;
    if (!date) {
      return res.status(400).json({ error: true, msg: "Missing 'date' in request parameters" });
    }

    const tasks = await req.db.from('Tasks').select("*").where("userId", "=", req.email).andWhere("date", "=", date);
    res.json(tasks);
  } catch (err) {
    next(err);
  }
});

// GET a specific task by id
router.get('/tasks/:id', authorize, async (req, res, next) => {
  try {
    const tasks = await req.db.from('Tasks').select("*").where("id", "=", req.params.id).andWhere("userId", "=", req.email);
    if (tasks.length === 0) {
      return res.status(404).json({ error: true, msg: "Task not found" });
    }
    res.json(tasks[0]);
  } catch (err) {
    next(err);
  }
});

// POST a new task
router.post('/tasks', authorize, async (req, res, next) => {
  const { title, color, priority, completed, date } = req.body;
  if (!title || !date || !priority) {
    return res.status(400).send("Request body incomplete - Please enter all required fields");
  }

  try {
    const [id] = await req.db.from('Tasks').insert({ title, color, priority, completed, date, userId: req.email });
    const task = await req.db.from('Tasks').select('*').where('id', '=', id);
    res.status(201).json({
      msg: "Task created",
      task: task[0]
    });
  } catch (err) {
    next(err);
  }
});

// PUT update a task
router.put('/tasks/:id', authorize, async (req, res, next) => {
  const { id, title, color, priority, completed, date } = req.body;
  if (!title || !date || !priority) {
    return res.status(400).send("Request body incomplete - Please enter all required fields");
  }

  try {
    await req.db.from('Tasks').where("id", "=", req.params.id).andWhere("userId", "=", req.email).update({ title, color, priority, completed, date });
    const task = await req.db.from('Tasks').select('*').where('id', '=', req.params.id);
    res.json({
      msg: "Task updated",
      task: task[0]
    });
  } catch (err) {
    next(err);
  }
});

// PUT update a task's completed status
router.put('/tasks/:id/completed', authorize, async (req, res, next) => {
  try {
    const { completed } = req.body;
    if (completed === undefined) {
      return res.status(400).json({ error: true, msg: "Missing 'completed' in request body" });
    }

    const task = await req.db.from('Tasks').select("*").where("id", "=", req.params.id).andWhere("userId", "=", req.email);
    if (task.length === 0) {
      return res.status(404).json({ error: true, msg: "Task not found" });
    }

    await req.db.from('Tasks').where("id", "=", req.params.id).update({ completed });
    res.json({ success: true, msg: "Task's completed status updated" });
  } catch (err) {
    next(err);
  }
});

// DELETE a task
router.delete('/tasks/:id', authorize, async (req, res, next) => {
  try {
    await req.db.from('Tasks').where("id", "=", req.params.id).andWhere("userId", "=", req.email).del();
    res.json({ msg: "Task deleted" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
