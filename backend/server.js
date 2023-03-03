require("dotenv").config();
const {MONGO_URL,FRONT_URL,SECRET_SESSION} = process.env
const mongoose = require("mongoose");
const express = require("express");
const cors = require("cors");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require('connect-mongodb-session')(session);
const bodyParser = require("body-parser");
const app = express();
const User = require("./user");

//----------------------------------------- END OF IMPORTS---------------------------------------------------

const connection = mongoose.connect(
  MONGO_URL,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => {
    console.log("Mongoose Is Connected");
  }
);

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  cors({
    origin: FRONT_URL, // <-- location of the react app were connecting to
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", FRONT_URL);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
  next();
});

const store = new MongoStore({
  uri: MONGO_URL,
  collection: 'sessions',
  expires: 1000 * 60 * 60 * 24 // tiempo de expiración de la sesión
});

app.set('trust proxy', 1);

app.use(session({
  secret: SECRET_SESSION,
  resave: false,
  saveUninitialized: true,
  store: store,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // tiempo de vida de la cookie
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    // domain: '.vercel.app' // Establecer el dominio de la cookie
  }
}));

app.use(cookieParser(SECRET_SESSION));
app.use(passport.initialize());
app.use(passport.session());
require("./passportConfig")(passport);

//----------------------------------------- END OF MIDDLEWARE---------------------------------------------------

// Routes
// ROUTE PASSPORT-LOCAL
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) throw err;
    if (!user) res.send("No User Exists");
    else {
      req.logIn(user, (err) => {
        if (err) throw err;
        res.send("Successfully Authenticated");
     
      });
    }
  })(req, res, next);
});
app.post("/register", (req, res) => {
  User.findOne({ username: req.body.username }, async (err, doc) => {
    if (err) throw err;
    if (doc) res.send("User Already Exists");
    if (!doc) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);

      const newUser = new User({
        username: req.body.username,
        password: hashedPassword,
      });
      await newUser.save();
      res.send("User Created");
    }
  });
});

// ROUTES AUTH GOOGLE
//primer PASO, cuando esto termine va a llamar al callback /GOOGLE/CALLBACK, ya sea si fue exitoso o si fue con error , ESTO SE CONFIGURA GRACIAS AL CALLBACK DE PASSPORT.JS en la ESTRATEGIA DE GOOGLE
app.get(
  "/auth/google",
  passport.authenticate('google', {  scope: ['profile', 'email'] })
);

// segundo paso, cuando se termina la estrategia, se manda a llamar este callback y redirije segun si fue exitoso o si falló
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: `${FRONT_URL}/session/error` }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect(FRONT_URL);
  }
);

// ROUTE GET USER
// esta ruta no esta protegiada, simplemente obtiene la info de la sesion si es que existe
app.get("/user", (req, res) => {
  console.log(req.user)
  res.send(req.user); // The req.user stores the entire user that has been authenticated inside of it.
});

// ROUTE LOGOUT
app.post('/logout', (req, res) => {
  req.logout();
  res.redirect(FRONT_URL);
});

//----------------------------------------- END OF ROUTES---------------------------------------------------
//Start Server
const PORT = process.env.PORT || 4000
  
    app.listen(PORT, () => {
      console.log(`Server is listening on PORT: ${PORT}`);
    });

