const express = require("express");
const {
  googleAuthRequest,
  googleAuthValidate,
  getUserDataFromToken,
} = require("../controllers/userController");
const router = express.Router();


//google auth request
router.post("/googleLoginReq", googleAuthRequest);
//google auth validate
router.get("/googleLoginValidate", googleAuthValidate);
//getUserDataFromToken
router.post("/getUserDataFromToken" , getUserDataFromToken);

module.exports = router;
