import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";

const { Pool } = pg;
const app = express();
const port = 9000;
const saltRounds = 15;

env.config();

app.use(express.static("public"));

app.use(bodyParser.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DATABASE,
  password: process.env.POSTGRES_PASSWORD,
});
pool.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/login/register", (req, res) => {
  res.redirect("/register");
});
app.get("/register/login", (req, res) => {
  res.redirect("/login");
});
app.get("/home", (req, res) => {
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const userid = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await pool.query(
      "SELECT * FROM users WHERE userid = $1",
      [userid]
    );

    if (checkResult.rows.length > 0) {
      res.send("<h1>userid already exists. Try logging in.</h1>");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          await pool.query(
            "INSERT INTO users (userid, password_hash, role) VALUES ($1, $2, 'basic')",
            [userid, hash]
          );
          res.redirect("/login");
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const userid = req.body.username;
  const loginPassword = req.body.password;
  try {
    const result = await pool.query("SELECT * FROM users WHERE userid = $1", [
      userid,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const data = {
        userid: user.userid,
        role: user.role,
      };
      const storedHashedPassword = user.password_hash;
      bcrypt.compare(
        loginPassword,
        storedHashedPassword,
        async (err, result) => {
          if (err) {
            console.error("Error comparing passwords:", err);
          } else {
            if (result && data.role === "admin") {
              const totalUsers = await pool.query("SELECT * FROM users");

              const allUserData = totalUsers.rows.map((user) => ({
                userid: user.userid,
                role: user.role,
              }));

              const objectAll = { allUserData, ...data };
              res.render("inside.ejs", objectAll);
            } else if (result) {
              res.render("inside.ejs", data);
            } else {
              res.send("<h1>Incorrect Password</h1>");
            }
          }
        }
      );
    } else {
      res.send("<h1>User not found</h1>");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Backend server is running on http://localhost:${port}`);
});

export default app;
