require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = process.env.SALTROUNDS;


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
});



//userSchema.plugin(encrypt, { secret: process.env.SECRETKEY, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

app.get('/', (req, res) => {
    res.render("home");
})

app.get('/login', (req, res) => {
    res.render("login");
})

app.get('/register', (req, res) => {
    res.render("register");
})

app.post('/register', (req, res) => {

    bcrypt.genSalt(saltRounds, function (err, salt) {
        bcrypt.hash(req.body.password, salt, function (err, hash) {

            const newUser = new User({
                email: req.body.username,
                //password: md5(req.body.password)
                password: hash
            })
            newUser.save((err) => {
                if (err) {
                    console.log(err);
                }
                else {
                    res.render("secrets")
                }
            })

        });
    });


})

app.post('/login', (req, res) => {
    const userEmail = req.body.username;
    //const userPwd = md5(req.body.password);
    const userPwd = req.body.password;

    User.findOne({ email: userEmail }, (err, foundUser) => {
        if (err) {
            console.log(err)
        }
        else {
            if (foundUser) {

                bcrypt.compare(userPwd, foundUser.password, function (err, result) {
                    if (result === true) {
                        res.render('secrets');
                    }
                    else {
                        res.redirect('/');
                    }
                });

                // if (foundUser.password === userPwd) {
                //     res.render('secrets');
                // }
                // else {
                //     res.redirect('/');
                // }
            }
        }
    })

})


app.listen(3000, () => {
    console.log("Server running in port 3000");
})