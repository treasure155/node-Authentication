const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./models/User');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET, resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });

      if (!user || !user.validPassword(password)) {
        return done(null, false, { message: 'Invalid username or password' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
}, (accessToken, refreshToken, profile, done) => {
  process.nextTick(async () => {
    try {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = new User({
          googleId: profile.id,
          displayName: profile.displayName,
        });
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  });
}));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: process.env.FACEBOOK_CALLBACK_URL,
}, (accessToken, refreshToken, profile, done) => {
  process.nextTick(async () => {
    try {
      let user = await User.findOne({ facebookId: profile.id });

      if (!user) {
        user = new User({
          facebookId: profile.id,
          displayName: profile.displayName,
        });
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.post('/', passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/dashboard');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, password, displayName, profilePicture, skills, occupation, country, city, phoneNumber, interests, gender, maritalStatus } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.render('register', { error: 'Username already exists', username, displayName, profilePicture, skills, occupation, country, city, phoneNumber, interests, gender, maritalStatus });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      displayName,
      profilePicture,
      skills,
      occupation,
      country,
      city,
      phoneNumber,
      interests,
      gender,
      maritalStatus,
    });

    await newUser.save();

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    console.log('User Data:', user);

    res.render('dashboard', { user });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/');
}

app.get('/edit-profile', isAuthenticated, (req, res) => {
  res.render('edit-profile', { user: req.user });
});

app.post('/edit-profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      displayName,
      profilePicture,
      skills,
      occupation,
      country,
      city,
      phoneNumber,
      interests,
      gender,
      maritalStatus,
    } = req.body;

    await User.findByIdAndUpdate(userId, {
      displayName,
      profilePicture,
      skills,
      occupation,
      country,
      city,
      phoneNumber,
      interests,
      gender,
      maritalStatus,
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
