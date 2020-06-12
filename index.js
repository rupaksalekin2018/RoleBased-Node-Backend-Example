const cors = require("cors");
const exp = require("express");
const bp = require("body-parser");
const { success, error } = require("consola");
const { connect } = require("mongoose");
const passport = require("passport");

//Bring in the app constraints
const { DB, PORT } = require("./config");

//Initialize the application
const app = exp();

//Middleware
app.use(cors());
app.use(bp.json());
app.use(passport.initialize());

require("./middlewares/passport")(passport);

//Connection with DB

const startApp = async () => {
  try {
    // Connection With DB
    await connect(DB, {
      useFindAndModify: true,
      useUnifiedTopology: true,
      useNewUrlParser: true,
    });

    success({
      message: `Successfully connected with the Database \n${DB}`,
      badge: true,
    });

    // Start Listenting for the server on PORT
    app.listen(PORT, () =>
      success({ message: `Server started on PORT ${PORT}`, badge: true })
    );
  } catch (err) {
    error({
      message: `Unable to connect with Database \n${err}`,
      badge: true,
    });
    startApp();
  }
};

//User Router Middleware

app.use("/api/users", require("./routes/users"));
app.get("/", (req, res) => {
  res.send("Hello!");
});

startApp();
