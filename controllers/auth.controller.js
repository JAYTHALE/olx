//admin register
//admin otp verify
//admin login
//admin logout

//user register
//user otp verify
//user login
//user logout 

const asyncHandler = require("express-async-handler")
const validator = require("validator")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { checkEmpty } = require("../utils/CheckEmpty")
const Admin = require("../models/Admin")
const sendEmail = require("../utils/Email")
const User = require("../models/User")


exports.registerAdmin = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body
    const { isError, error } = checkEmpty({ name, email, password })
    if (isError) {
        return res.status(400).json({ message: "ALL Feilds Required", error })
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Invalid Email" })
    }
    // if (!validator.isStrongPassword(password)) {
    //     return res.status(400).json({ message: "Provide Strong password" })
    // }
    const isFound = await Admin.findOne({ email })
    if (isFound) {
        return res.status(400).json({ message: "Email already registered With Us" })
    }
    const hash = await bcrypt.hash(password, 10)
    await Admin.create({ name, email, password: hash })

    res.json({ message: "register success" })
})

exports.loginAdmin = asyncHandler(async (req, res) => {
    const { email, password } = req.body
    const { isError, error } = checkEmpty({ email, password })
    if (isError) {
        return res.status(401).json({ message: "All Fields required" })
    }
    if (!validator.isEmail(email)) {
        return res.status(401).json({ message: "Invalid Email" })
    }
    const result = await Admin.findOne({ email })
    if (!result) {
        return res.status(401).json({ measage: "Email Not Found" })
    }
    const isVerify = await bcrypt.compare(password, result.password)

    if (!isVerify) {
        return res.status(401).json({
            measage: process.env.NODE_ENV === "development" ?
                "Invalid Password" : "Invalid Credentials"
        })
    }

    //sent OTP
    const otp = Math.floor(10000 + Math.random() * 900000)
    await Admin.findByIdAndUpdate(result._id, { otp })
    await sendEmail({
        to: email,
        subject: `Login otp`,
        message: `<h1>Do Not your Account OTP</h1> <p>your Login OTP${otp}</p>`
    })
    res.json({ message: "Credentials Verify Success OTP Send To Your Registered Email" })

})

exports.verifyOTP = asyncHandler(async (req, res) => {
    const { otp, email } = req.body
    const { isError, error } = checkEmpty({ email, otp })
    if (isError) {
        return res.status(401).json({ message: "All Fields required", error })
    }
    if (!validator.isEmail(email)) {
        return res.status(401).json({ message: "Invalid Email" })
    }
    const result = await Admin.findOne({ email })
    if (!result) {
        return res.status(401).json({
            measage: process.env.NODE_ENV === "development" ?
                "Invalid Email" : "Invalid Credentials"
        })
    }
    if (otp !== result.otp) {
        return res.status(401).json({ message: "Invalid OTP" })
    }

    const token = jwt.sign({ userId: result._id }, process.env.JWT_KEY, { expiresIn: "1d" })

    //JWT
    res.cookie("admin", token, {
        maxAge: 86400000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'development'
    })

    //Cookie
    res.json({
        message: "OTP veerify Success..", result: {
            _id: result._id,
            name: result.name,
            email: result.email
        }
    })
    //Res
})

exports.logoutAdmin = asyncHandler(async (req, res) => {
    res.clearCookie("admin")
    res.json({ message: "Admin Logout Success" })
})

exports.registerUser = asyncHandler(async (req, res) => {
    const { name, mobile, email, password, ConformPassword } = req.body
    const { error, isError } = checkEmpty({
        name,
        mobile,
        email,
        password,
        ConformPassword
    })
    if (isError) { return res.status(400).json({ message: "All Fields Required", error }) }
    if (!validator.isEmail(email)) { return res.status(400).json({ message: "Invalid Email" }) }
    if (!validator.isMobilePhone(mobile, "en-IN")) { return res.status(400).json({ message: "Invalid mobile" }) }
    if (!validator.isStrongPassword(password)) { return res.status(400).json({ message: " Provied Strong password" }) }
    if (!validator.isStrongPassword(ConformPassword)) { return res.status(400).json({ message: "Provied Strong ConformPassword" }) }
    if (password !== ConformPassword) { return res.status(400).json({ message: "Password Do not match" }) }

    const hash = await bcrypt.hash(password, 10)

    await User.create({ name, mobile, email, password: hash })

    res.json({ message: "User Register Success" })

})

exports.loginUser = asyncHandler(async (req, res) => {
    const { email, password } = erq.body
    const { error, isError } = checkEmpty({ email, password })
    if (isError) { return res.status(400).json({ message: "All Fields Required", error }) }
    const result = await User.findOne({ email })

    if (!result) {
        return res.status(400).json({ message: "Email Not Found" })
    }

    const verify = await bcrypt.compare(password, result.password)
    if (!verify) {
        return res.status(400).json({ message: "Password Do Not match" })
    }
    const token = jwt.sign({ userID: result._id }, process.env.JWT_KEY, { expiresIn: "180d" })

    res.cookie("user", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 1000 * 60 * 60 * 24 * 180
    })
    res.json({ message: "User Login Success" })
})

exports.logoutUser = asyncHandler(async (req, res) => {
    res.clearCookie("user")
    res.json({ message: "User Logout Success" })
})


