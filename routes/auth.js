const express = require("express");
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetchuser = require('../middleware/fetchuser');

const JWt_SECRET = 'Sufyanisagoodboy$';
// ROUTE 1 :Create a User using: POST "/api/auth/createuser". No Login require

router.post("/createuser", [
    body('name', "Enter a Valid Name").isLength({ min: 3 }),
    body('email', "Enter a Valid Email").isEmail(),
    body('password', "Password must be atleast 5 Characters").isLength({ min: 5 }),

], async (req, res) => {
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    //Check whether the user with this email exists already
    try {
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json({ error: "Sorry a user with this email is already exists" })
        }

        const Salt = await bcrypt.genSalt(10);
        const secPassword = await bcrypt.hash(req.body.password, Salt)
        // Create a new User
        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: secPassword,
        })

        const data = {
            user: {
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWt_SECRET)
        res.json({ authToken })

    } catch (error) {
        console.error(error.message)
        res.status(500).send("Some Error occured")
    }
});

// ROUTE 2 : Authenticate a User using: POST "/api/auth/login". No Login require

router.post("/login", [
    body('email', "Enter a Valid Email").isEmail(),
    body('password', "Password Can't be blank").exists(),
], async (req, res) => {
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ error: "Please try to login with Correct Credentials" })
        }
        const passwordCompare = await bcrypt.compare(password,user.password)
        if (!passwordCompare) {
            return res.status(400).json({ error: "Please try to login with Correct Credentials" })
        }
        const data = {
            user: {
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWt_SECRET)
        res.json({ authToken })

    } catch (error) {
        console.error(error.message)
        res.status(500).send("Some Error occured")
    }
})

// ROUTE 3 : Get loggedin User Details using: POST "/api/auth/getuser". Login require

router.post("/getuser", fetchuser,async(req,res)=>{

    try {
        userId = req.user.id
        const user = await User.findById(userId).select("-password")
        res.send(user)
    } catch (error) {
        console.error(error.message)
        res.status(500).send("Some Error occured")
    }
})


module.exports = router