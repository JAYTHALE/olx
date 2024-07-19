const mongoose = require("mongoose")
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    isdeleted: {
        type: Boolean,
        default: false
    },
    verified: {
        type: Boolean,
        default: false
    },
    active: {
        type: Boolean,
        default: true
    },
    mobile: {
        type: Boolean,
        required: true
    },
    code: {
        type: String,
    },
    avatar: {
        type: String,
        default: "https://res.cloudinary.com/dysyjf2yd/image/upload/v1721291319/head-659651_1280_qet0fk.png"
    },
}, { timestamps: true })

module.exports = mongoose.model("user", userSchema)