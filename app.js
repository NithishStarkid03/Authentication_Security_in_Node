require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = process.env.SALTROUNDS;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');



const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'createsession!',
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
});



//userSchema.plugin(encrypt, { secret: process.env.SECRETKEY, encryptedFields: ["password"] });

userSchema.plugin(passportLocalMongoose);



const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', (req, res) => {
    res.render("home");
})

app.get('/login', (req, res) => {
    res.render("login");
})

app.get('/register', (req, res) => {
    res.render("register");
})

app.get('/secrets', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('secrets');
    }
    else {
        res.redirect('/login');
    }
})

app.get('/logout', function (req, res) {
    req.logout((err) => {
        if (!err) {
            res.redirect('/');
        }
    });

})

app.post('/register', (req, res) => {

    // bcrypt.genSalt(saltRounds, function (err, salt) {
    //     bcrypt.hash(req.body.password, salt, function (err, hash) {

    //         const newUser = new User({
    //             email: req.body.username,
    //             //password: md5(req.body.password)
    //             password: hash
    //         })
    //         newUser.save((err) => {
    //             if (err) {
    //                 console.log(err);
    //             }
    //             else {
    //                 res.render("secrets")
    //             }
    //         })

    //     });
    // });

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect('/register');
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect('/secrets')
            })
        }
    })


})

app.post('/login', (req, res) => {
    // const userEmail = req.body.username;
    // //const userPwd = md5(req.body.password);
    // const userPwd = req.body.password;

    // User.findOne({ email: userEmail }, (err, foundUser) => {
    //     if (err) {
    //         console.log(err)
    //     }
    //     else {
    //         if (foundUser) {

    //             bcrypt.compare(userPwd, foundUser.password, function (err, result) {
    //                 if (result === true) {
    //                     res.render('secrets');
    //                 }
    //                 else {
    //                     res.redirect('/');
    //                 }
    //             });

    //             // if (foundUser.password === userPwd) {
    //             //     res.render('secrets');
    //             // }
    //             // else {
    //             //     res.redirect('/');
    //             // }
    //         }
    //     }
    // })

    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect('/secrets');
            })
        }
    })




})


app.listen(3000, () => {
    console.log("Server running in port 3000");
})