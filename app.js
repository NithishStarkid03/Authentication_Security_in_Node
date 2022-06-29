const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
});

const secretkey = "AtotheBtotheCtotheD."

userSchema.plugin(encrypt, { secret: secretkey, encryptedFields: ["password"] });

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
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    })

    newUser.save((err) => {
        if (err) {
            console.log(err);
        }
        else {
            res.render("secrets")
        }
    })
})

app.post('/login', (req, res) => {
    const userEmail = req.body.username;
    const userPwd = req.body.password;

    User.findOne({ email: userEmail }, (err, foundUser) => {
        if (err) {
            console.log(err)
        }
        else {
            if (foundUser) {
                if (foundUser.password === userPwd) {
                    res.render('secrets');
                }
                else {
                    res.redirect('/');
                }
            }
        }
    })

})


app.listen(3000, () => {
    console.log("Server running in port 3000");
})