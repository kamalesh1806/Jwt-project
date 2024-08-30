require('dotenv').config();
const db = require('./config/database');
const auth = require('./middleware/auth');

const express = require('express');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const User = db.user;

app.use(express.json());

const { API_PORT } = process.env;
const port = process.env.PORT || API_PORT;
db.sequelize.sync().then(result => {
    app.listen(port, () => {
    console.log(`Server running on port ${port}`);
      })
        });


app.post("/register", async (req, res) => {

  try {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    if (!(email && password && name)) {
      res.status(400).send("All input is required");
    }


    const oldUser = await User.findOne({ where: { email: email }});

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }


    encryptedPassword = await bcrypt.hash(password, 10);


    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

  
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );

    user.token = token;

    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }

});


app.post("/login", async (req, res) => {

    try {
 
      const { email, password } = req.body;
  
 
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
   
      const user = await User.findOne({ where: { email: email }});
  
      if (user && (await bcrypt.compare(password, user.password))) {

        const token = jwt.sign(
          { user_id: user._id, email },
          process.env.TOKEN_KEY,
          {
            expiresIn: "2h",
          }
        );
  
      
        user.token = token;
  
    
        res.status(200).json(user);
      }
      res.status(400).send("Invalid Credentials");
    } catch (err) {
      console.log(err);
    }
  });

app.get("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome 🙌 ");
});
