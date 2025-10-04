const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../util/sendEmail");

//  Google auth request
const {OAuth2Client} = require('google-auth-library');

//generate token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

//login
const userLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  //Validate request
  if (!email || !password) {
    res.status(400);
    throw new Error("Invalid user data");
  }
  //check if user exist
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("Please enter a valid email");
  }

  //check if password match
  const isMatch = await bcrypt.compare(password, user.password);

  if (isMatch) {
    const token = generateToken(user._id);
    //exclude password
    res.status(200).json({
      _id: user._id,
      sId: user.sId,
      fullName: user.fullName,
      email: user.email,
      mobileNo: user.mobileNo,
      dob: user.dob,
      address: user.address,
      year: user.year,
      type: user.type,
      photo: user.photo,
      department: user.department,
      dateOfEntry: user.dateOfEntry,
      shortName: user.shortName,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Please check your password");
  }
});

//User user details -user
const getUserprofile = asyncHandler(async (req, res) => {
  const id = req.person._id;
  const personType = req.personType;

  if (personType === "manager") {
    res.status(401);
    throw new Error("Not authorized , Please login as a user");
  }

  //exclude password
  const user = await User.findById(id).select("-password");

  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

//get user by id
const getUserById = asyncHandler(async (req, res) => {
  const id = req.params.id;
  const personType = req.personType;

  if (personType === "user") {
    res.status(401);
    throw new Error("Not authorized , Please login as a manager");
  }

  //exclude password
  const user = await User.findById(id).select("-password");

  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

//get all users
const getAllUsers = asyncHandler(async (req, res) => {
  const personType = req.personType;

  if (personType === "user") {
    res.status(401);
    throw new Error("Not authorized , Please login as a manager");
  }

  const users = await User.find({}).select("-password");

  if (users) {
    res.status(200).json(users);
  } else {
    res.status(404);
    throw new Error("Users not found");
  }
});

//change password  --user
const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const id = req.person._id;
  const personType = req.personType;

  if (personType === "manager") {
    res.status(401);
    throw new Error("Not authorized , Please login as a user");
  }

  //check if user exist
  const user = await User.findById(id);

  if (!user) {
    res.status(400);
    throw new Error("Invalid user data");
  }

  //check if password match
  const isMatch = await bcrypt.compare(currentPassword, user.password);

  if (isMatch) {
    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    //update password
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { password: hashedPassword },
      { new: true }
    );

    if (updatedUser) {
      res.status(200).json({ message: "Password updated successfully" });
    } else {
      res.status(400);
      throw new Error("Something went wrong");
    }
  } else {
    res.status(400);
    throw new Error("Invalid current password");
  }
});

//forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  //exclude password
  const user = await User.findOne({ email }).select("-password");

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  //delete token if it exits in DB
  let token = await Token.findOne({ userId: user._id });

  if (token) {
    await token.deleteOne();
  }

  //Create reset token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;

  //Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //Save token  to DB

  await new Token({
    userId: user._id,
    token: hashedToken,
    createAt: Date.now(),
    expiresAt: Date.now() + 30 * 60 * 1000,
  }).save();

  //construct reset URL
  const resetURL = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  //Reset email
  const message = `
  <h2>Hello ${user.fullName}</h2>
  <p>Please use the url below to reset your password</p>
  <p>This reset link is valid for only 30 minutes</p>
  <a href=${resetURL} clicktracking=off>${resetURL}</a>
  <p>Regards KTS</p>
  `;

  const subject = "Password Reset Request";
  const sent_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, sent_to, sent_from);
    res.status(200).json({ success: true, message: "Reset Email Sent" });
  } catch (err) {
    res.status(500);
    throw new Error("Email didn't not sent,Please try again");
  }
});

//reset password
const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  if (!password) {
    res.status(400);
    throw new Error("Please enter a password");
  }

  //Hash token  then compare with token in the DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // find token in DB
  const userTokenDb = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userTokenDb) {
    res.status(404);
    throw new Error("Invalid or expired token");
  }

  //Find user
  const user = await User.findOne({ _id: userTokenDb.userId });
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  user.password = hashedPassword;
  await user.save();

  //Delete token from DB
  await userTokenDb.deleteOne();

  res.status(200).json({ message: "Password reset successful,Please login" });
});


const googleAuthRequest=asyncHandler(async(req,res)=>{
  const redirectURL = `${process.env.BACKEND_URL}/api/auth/googleLoginValidate`;
  console.log('redirectURL :>> ', redirectURL);
  console.log('process.env.CLIENT_ID :>> ', process.env.CLIENT_ID);
  console.log('process.env.CLIENT_SECRET :>> ', process.env.CLIENT_SECRET);
  
  const oAuth2Client = new OAuth2Client(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    redirectURL
    );

    // Generate the url that will be used for the consent dialog.
    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: 'https://www.googleapis.com/auth/userinfo.email  openid profile',
      prompt: 'consent'
    });
    const urlObj = new URL(authorizeUrl);
    console.log('client_id param:', urlObj.searchParams.get('client_id'));

    res.json({url:authorizeUrl})
})

// validate google account
const googleAuthValidate=asyncHandler(async(req,res)=>{

  try {
    const code = req.query.code;
    if(!code){
      throw new Error('Code is not available');
    }

    const redirectURL = `${process.env.BACKEND_URL}/api/auth/googleLoginValidate`;

    const oAuth2Client = new OAuth2Client(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      redirectURL
    );

    // Exchange the authorization code for access tokens
    const { tokens } = await oAuth2Client.getToken(code);
    // console.log(tokens);
    oAuth2Client.setCredentials(tokens);

    // Get user profile information
    const ticket = await oAuth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const email = payload.email;
    const fullName =
        payload?.name ||
        [payload?.given_name, payload?.family_name].filter(Boolean).join(" ") ||
        (email ? email.split("@")[0] : "GoogleUser");
    const photo = payload?.picture || "";
    // console.log(email);

    let user = await User.findOne({ email });

    if (!user) {
      const makeShortName = (name) => {
        if (!name) return "GG";
        return name
          .split(" ")
          .map((n) => n[0])
          .join("")
          .slice(0, 4)
          .toUpperCase();
      };

      // sId generation (D/BCS/YY/XXXX)
      const faculty = "D";
      const dept = "BCS";
      const yearTwoDigits = new Date().getFullYear().toString().slice(-2);
      const sIdPrefix = `${faculty}/${dept}/${yearTwoDigits}/`;
      const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const prefixRegex = `^${escapeRegex(sIdPrefix)}`;

      let seqNum = 0;
      let generatedSId;
      for (let attempt = 0; attempt < 5; attempt++) {
        const existingCount = await User.countDocuments({ sId: { $regex: prefixRegex } });
        seqNum = existingCount + 1 + attempt;
        const seqStr = String(seqNum).padStart(4, "0");
        generatedSId = `${sIdPrefix}${seqStr}`;
        const exists = await User.exists({ sId: generatedSId });
        if (!exists) break;
      }

      const generatedShortName = makeShortName(fullName);
      const defaultDepartment = dept;
      const defaultYear = yearTwoDigits;
      const defaultDOB = new Date("1970-01-01");
      const defaultDateOfEntry = Date.now();
      const defaultType = "student"; // must be 'student' or 'lecture'
      const defaultPhoto = photo || "https://res.cloudinary.com/dnoobzfxo/image/upload/v1717409638/istockphoto-1475805651-612x612_yhdgye.jpg";
      const generatedMobile = `+000${Date.now().toString().slice(-7)}`;

      // random password for schema: hash it
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(randomPassword, salt);

      const newUserData = {
        sId: generatedSId,
        fullName,
        email,
        photo: defaultPhoto,
        password: hashedPassword,
        mobileNo: generatedMobile,
        dob: defaultDOB,
        address: "Not provided",
        year: defaultYear,
        dateOfEntry: defaultDateOfEntry,
        type: defaultType,
        department: defaultDepartment,
        shortName: generatedShortName,
      };

      user = await User.create(newUserData);
    }

    const jwtToken = generateToken(user._id);
    const redirectBase = `${process.env.FRONTEND_URL}/login`;
    const query = `?token=${encodeURIComponent(jwtToken)}`;
    return res.redirect(
      safeFrontendUrl('/login', { token: encodeURIComponent(jwtToken) })
    );

  } catch(err) {
    console.error('Google auth failed:', err);     // log server-side
    return res.redirect(
      safeFrontendUrl('/login', { error: 'oauth_failed' })  // fixed code, no raw message
    );
  }
})

//sent the user data from the token to the frontend
const getUserDataFromToken = asyncHandler(async (req, res) => {

  const {token} = req.body

  console.log(req.body);
  if (!token) {
    res.status(400);
    throw new Error("Token is required");
  }
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await User.findById(decoded.id).select("-password");
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  console.log(user);
  res.status(200).json({
    _id: user._id,
    sId: user.sId,
    fullName: user.fullName,
    email: user.email,
    mobileNo: user.mobileNo,
    dob: user.dob,
    address: user.address,
    year: user.year,
    type: user.type,
    photo: user.photo,
    department: user.department,
    dateOfEntry: user.dateOfEntry,
    shortName: user.shortName,
    token,
  });

});

module.exports = {
  getAllUsers,
  userLogin,
  getUserprofile,
  getUserById,
  changePassword,
  forgotPassword,
  resetPassword,
  googleAuthRequest,
  googleAuthValidate,
  getUserDataFromToken
};
