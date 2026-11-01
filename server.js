const dotenv = require('dotenv');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
dotenv.config();
app.use(express.json());

// Schema: describes the shape of one journal entry.
const journalSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    month: { type: Number, required: true, min: 1, max: 12 },
    day: { type: Number, required: true, min: 1, max: 31 },
    content: { type: String, required: true, trim: true },
  },
  { timestamps: true }
);

// Model: the class we use to read and write the 'journals' collection.
// One entry per user per day. The index also stops a second POST for the same day.
journalSchema.index({ user: 1, month: 1, day: 1 }, { unique: true });

const Journal = mongoose.model('Journal', journalSchema);

// Small helper so every catch block reports errors the same way.
function sendError(res, err) {
  if (err.name === 'ValidationError' || err.name === 'CastError') {
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  return res.status(500).json({ error: 'Something went wrong' });
}

// Checks the "Authorization: Bearer <token>" header and stores the user id on the request.
function requireLogin(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Log in first: send Authorization: Bearer <token>' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token is missing, invalid or expired' });
  }
}

// Stops a logged-in user from reading or changing someone else's data.
// The id in the URL must match the id inside the token.
function requireOwner(req, res, next) {
  const urlId = req.params.userId || req.params.id;
  if (urlId !== req.userId) {
    return res.status(403).json({ error: 'You can only access your own data' });
  }
  next();
}

// ---------- Users: the 'users' collection, register and login ----------

// Schema for the 'users' collection. select: false keeps the password hash
// out of normal queries, so it is only loaded when we ask for it explicitly.
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, select: false },
    isAdmin: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Model: the class we use to read and write the 'users' collection.
const User = mongoose.model('User', userSchema);

// Runs after requireLogin. It reads the user from the database, not the token,
// so removing admin rights takes effect at once, even while a token is still valid.
async function requireAdmin(req, res, next) {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admins only' });
    }
    next();
  } catch (err) {
    sendError(res, err);
  }
}

// Only these fields ever leave the server - never the password hash.
function publicUser(user) {
  return { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin, createdAt: user.createdAt };
}

// POST /auth/register - create a new account
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'password must be at least 8 characters' });
    }
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash });
    res.status(201).json(publicUser(user));
  } catch (err) {
    sendError(res, err);
  }
});

// POST /auth/login - check the email and password, then hand back a token
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }
    // Ask for the password explicitly, because select: false hides it by default.
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const matches = await bcrypt.compare(password, user.password);
    if (!matches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // The token carries the user id in "sub" and expires after one hour.
    const token = jwt.sign({ sub: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: publicUser(user) });
  } catch (err) {
    sendError(res, err);
  }
});

// GET /admin/users - list every account (admins only)
app.get('/admin/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users.map(publicUser));
  } catch (err) {
    sendError(res, err);
  }
});

// GET /users/:id - read one account (own account only)
app.get('/users/:id', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(publicUser(user));
  } catch (err) {
    sendError(res, err);
  }
});

// PATCH /users/:id - change name and/or email (own account only)
app.patch('/users/:id', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const updates = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.email !== undefined) updates.email = req.body.email;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'Send at least one of name or email' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(publicUser(user));
  } catch (err) {
    // 11000 is MongoDB's code for a duplicate value in a unique field (the email).
    if (err.code === 11000) {
      return res.status(409).json({ error: 'That email is already in use' });
    }
    sendError(res, err);
  }
});

// DELETE /users/:id - remove an account (own account only)
app.delete('/users/:id', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(204).end();
  } catch (err) {
    sendError(res, err);
  }
});

// ---------- Per-user journal: /:userId/:month and /:userId/:month/:day ----------

// Turns text like "3" into the number 3. Returns null for anything that isn't digits.
function parseWholeNumber(text) {
  if (!/^\d+$/.test(text)) {
    return null;
  }
  return Number(text);
}

// GET /:userId/:month - list one user's entries for a month
app.get('/:userId/:month', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    const entries = await Journal.find({ user: req.params.userId, month }).sort({ day: 1 });
    res.json(entries);
  } catch (err) {
    sendError(res, err);
  }
});

// POST /:userId/:month - create an entry for one day of the month (body: day, content)
app.post('/:userId/:month', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    const { day, content } = req.body;
    if (day === undefined || content === undefined) {
      return res.status(400).json({ error: 'day and content are required' });
    }
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const entry = await Journal.create({ user: user._id, month, day, content });
    res.status(201).json(entry);
  } catch (err) {
    // 11000 means this user already has an entry for that month and day.
    if (err.code === 11000) {
      return res.status(409).json({ error: 'This user already has an entry for that day' });
    }
    sendError(res, err);
  }
});

// GET /:userId/:month/:day - read one entry
app.get('/:userId/:month/:day', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    const day = parseWholeNumber(req.params.day);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    if (day === null || day < 1 || day > 31) {
      return res.status(400).json({ error: 'day must be a number from 1 to 31' });
    }
    const entry = await Journal.findOne({ user: req.params.userId, month, day });
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    res.json(entry);
  } catch (err) {
    sendError(res, err);
  }
});

// PUT /:userId/:month/:day - replace the content of one entry (body: content)
app.put('/:userId/:month/:day', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    const day = parseWholeNumber(req.params.day);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    if (day === null || day < 1 || day > 31) {
      return res.status(400).json({ error: 'day must be a number from 1 to 31' });
    }
    const { content } = req.body;
    if (content === undefined) {
      return res.status(400).json({ error: 'content is required' });
    }
    const entry = await Journal.findOneAndUpdate(
      { user: req.params.userId, month, day },
      { content },
      { new: true, runValidators: true }
    );
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    res.json(entry);
  } catch (err) {
    sendError(res, err);
  }
});

// PATCH /:userId/:month/:day - change the content only if it was sent (body: content)
app.patch('/:userId/:month/:day', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    const day = parseWholeNumber(req.params.day);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    if (day === null || day < 1 || day > 31) {
      return res.status(400).json({ error: 'day must be a number from 1 to 31' });
    }
    if (req.body.content === undefined) {
      return res.status(400).json({ error: 'Send content to change' });
    }
    const entry = await Journal.findOneAndUpdate(
      { user: req.params.userId, month, day },
      { content: req.body.content },
      { new: true, runValidators: true }
    );
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    res.json(entry);
  } catch (err) {
    sendError(res, err);
  }
});

// DELETE /:userId/:month/:day - remove one entry
app.delete('/:userId/:month/:day', requireLogin, requireOwner, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const month = parseWholeNumber(req.params.month);
    const day = parseWholeNumber(req.params.day);
    if (month === null || month < 1 || month > 12) {
      return res.status(400).json({ error: 'month must be a number from 1 to 12' });
    }
    if (day === null || day < 1 || day > 31) {
      return res.status(400).json({ error: 'day must be a number from 1 to 31' });
    }
    const entry = await Journal.findOneAndDelete({ user: req.params.userId, month, day });
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    res.status(204).end();
  } catch (err) {
    sendError(res, err);
  }
});

// Connect to MongoDB first, then start listening for requests.
const PORT = process.env.PORT;
const MONGO_URI = process.env.MONGO_URI;

async function start() {
  if (!MONGO_URI) {
    console.error('Database connection failed');
    process.exit(1);
  }
  if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is not set. Add it to .env before starting.');
    process.exit(1);
  }
  await mongoose.connect(MONGO_URI);
  console.log('Connected to MongoDB');

  app.listen(PORT, () => {
    console.log(`Journal API listening on http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});
