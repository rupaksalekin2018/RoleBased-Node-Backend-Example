const jwt = require("jsonwebtoken");
const psp = require("passport");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { SECRET } = require("../config/index");

//To register the user (Admin, Super_Admin, User)

const userRegister = async (userDets, role, res) => {
  try {
    //Validate the username
    let usernameNotTaken = await validateUserName(userDets.username);
    if (!usernameNotTaken) {
      return res.status(400).json({
        message: `Username is already Taken!`,
        success: false,
      });
    }
    //Validate the Email
    let emailNotRegistered = await validateEmail(userDets.email);
    if (!emailNotRegistered) {
      return res.status(400).json({
        message: `email is already registered!`,
        success: false,
      });
    }

    //Get the hashed password

    const hashedPassword = await bcrypt.hash(userDets.password, 12);

    //const new user

    const newUser = new User({
      ...userDets,
      password: hashedPassword,
      role: role,
    });

    await newUser.save();

    return res.status(201).json({
      message: "Hurry!  You are successfully registered! Now Login!",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Unable To Create Account!",
      success: false,
    });
  }
};

/**
 * @DESC To Login the user (ADMIN, SUPER_ADMIN, USER)
 */
const userLogin = async (userCreds, role, res) => {
  let { username, password } = userCreds;
  // First Check if the username is in the database
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).json({
      message: "Username is not found. Invalid login credentials.",
      success: false,
    });
  }
  // We will check the role
  if (user.role !== role) {
    return res.status(403).json({
      message: "Please make sure you are logging in from the right portal.",
      success: false,
    });
  }
  // That means user is existing and trying to signin fro the right portal
  // Now check for the password
  let isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    // Sign in the token and issue it to the user
    let token = jwt.sign(
      {
        user_id: user._id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      SECRET,
      { expiresIn: "7 days" }
    );

    let result = {
      username: user.username,
      role: user.role,
      email: user.email,
      token: `Bearer ${token}`,
      expiresIn: 168,
    };

    return res.status(200).json({
      ...result,
      message: "Hurray! You are now logged in.",
      success: true,
    });
  } else {
    return res.status(403).json({
      message: "Incorrect password.",
      success: false,
    });
  }
};

const validateUserName = async (username) => {
  let user = await User.findOne({
    username,
  });
  return user ? false : true;
  //   if (user) {
  //     return false;
  //   } else {
  //     return true;
  //   }
};

const validateEmail = async (email) => {
  let Email = await User.findOne({
    email,
  });

  return Email ? false : true;
};

const userAuth = psp.authenticate("jwt", { session: false });

const serializeUser = (user) => {
  return {
    username: user.username,
    email: user.email,
    name: user.name,
    _id: user._id,
    updatedAt: user.updatedAt,
    createdAt: user.createdAt,
  };
};

///Check Role Midddleware
const checkRole = (roles) => (req, res, next) => {
  if (roles.includes(req.user.role)) {
    return next();
  }
  return res.status(401).json({
    message: "Unauthorized",
    success: false,
  });
};
module.exports = {
  userRegister,
  userLogin,
  userAuth,
  serializeUser,
  checkRole,
};
