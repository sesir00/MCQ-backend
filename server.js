const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();

const saltRounds = 10;

//mySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "registration form"
});

db.connect((err) => {
  if(err){
    console.log("Error connecting to mySQL server. " ,err);
    return;
  }
  console.log('Connected to MySql');
});

//Express Middleware
app.use(cors());
app.use(express.json());

//register route
app.post('/registrationform', async (req, res) => {
  const {username, email, password} = req.body;
  if(!username || !email || !password){
    return res.status(400).json({error: 'All fields are required'});
  }

  try{
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const query = 'INSERT INTO form (`name`, `email`, `password`) VALUES (?, ?, ?) ';
    db.query(query, [username, email, hashedPassword], (err, results) =>{
      if(err){
        console.log('Error registering user.', err);
        res.status(500).json({error: 'Error registering user.'});
      }
      else{
        res.json({message: 'User registered successfully'});
      }
     
    });
  }catch(error){
    console.error('Error hashinh password.', error);
    res.status(500).json({error: 'error registering user'});
  }

});

//route for login
app.post('/login', (req, res) => {
  const {username, password} = req.body;

  //ensure both fields are provided
  if(!username || !password){
    return res.status(400).json({message: 'Username and password are required'});
  }

  //Query to find user by username
  const query = ' SELECT * FROM form WHERE name = ?';
  db.query(query, [username], async (err, results) => {
    if(err){
      console.error('Error fetching user data.', err);
      return res.status(500).json({ message: 'Internal server error'});
    }

    //check if user was found with that username
    if(results.length === 0){
      return res.status(401).json({message: 'Invalid username or password'});
    }

      const user = results[0];  // Retrieve the user's information from the query result

      // Compare the provided password with the hashed password in the database
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if(!isPasswordValid){
        // If the password does not match, return an error
        return res.status(401).json({ message: 'Invalid email or password' });
      }
      // If login is successful, return a success message
      res.json({success: true, message: 'Login successful'});
  });
});


// Route to get all questions with options
app.get('/questions', (req, res) => {
  const query = `
      SELECT q.question_id, q.question_text, o.option_id, o.option_text, o.is_correct
      FROM questions q
      JOIN options o ON q.question_id = o.question_id
      ORDER BY q.question_id, o.option_id;
  `;

  db.query(query, (err, results) => {
      if (err) {
          console.error('Error retrieving questions:', err);
          return res.status(500).json({ error: 'Failed to retrieve questions' });
      }

      // Structure the response to group options under each question
      const questions = results.reduce((acc, row) => {
          const { question_id, question_text, option_id, option_text, is_correct } = row;

          let question = acc.find(q => q.question_id === question_id);
          if (!question) {
              question = {
                  question_id,
                  question_text,
                  options: []
              };
              acc.push(question);
          }

          question.options.push({
              option_id,
              option_text,
              is_correct
          });

          return acc;
      }, []);

      res.json(questions);
  });
});


//start server 
const port = 3000;
app.listen(port, () => {
  console.log(`server started at port ${port}`);
});