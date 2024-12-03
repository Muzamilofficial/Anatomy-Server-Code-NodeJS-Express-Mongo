require("dotenv").config(); // Load environment variables
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const session = require("express-session");
const nodemailer = require("nodemailer");
const path = require("path");
const { Strategy: GoogleStrategy } = require("passport-google-oauth2");
const requestIp = require('request-ip');
const crypto = require("crypto"); // Add at the top to import crypto

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 443;
const IP_ADDRESS = process.env.IP_ADDRESS || "localhost";
const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key";
const SESSION_SECRET = process.env.SESSION_SECRET || "default_session_secret_key";
app.use("/assets", express.static(path.join(__dirname, "assets")));
let loggedInUserEmail = null;

// Middleware setup
app.use(cors());
app.use(bodyParser.json());



passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
      passReqToCallback: true,
    },
    async (request, accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          // Generate a strong 8-character password
          const generatedPassword = crypto.randomBytes(4).toString("hex");

          // Hash the generated password
          const hashedPassword = await bcrypt.hash(generatedPassword, 10);

          // Create a new user with the generated password
          user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
            password: hashedPassword, // Save hashed password in DB
          });

          await user.save();

          // Optionally send the password to the user's email
          const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: profile.emails[0].value,
            subject: "Welcome to Anatomy! Your Login Details",
            html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; background-color: #f9f9f9;">
                <div style="text-align: center; margin-bottom: 20px;">
                  <img src="cid:appLogo" alt="Anatomy Logo" style="max-width: 150px;" />
                </div>
                <h1 style="color: #333; text-align: center;">Welcome to Anatomy!</h1>
                <p style="color: #555; font-size: 16px; line-height: 1.5;">
                  Dear ${profile.displayName},<br/>
                  Welcome to Anatomy! We're excited to have you on board. Below are your login details:
                </p>
                <ul style="color: #555; font-size: 16px;">
                  <li><strong>Email:</strong> ${profile.emails[0].value}</li>
                  <li><strong>Password:</strong> ${generatedPassword}</li>
                </ul>
                <p style="color: #555; font-size: 16px; line-height: 1.5;">
                  Please use these credentials to log in and update your password if needed.
                </p>
                <div style="text-align: center; margin-top: 20px;">
                  <a href="http://www.yourcompany.com" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">Visit Anatomy</a>
                </div>
                <footer style="background-color: #333; color: white; padding: 10px; text-align: center; margin-top: 20px;">
                  <p style="font-size: 14px;">&copy; 2024 Anatomy. All Rights Reserved.</p>
                  <p style="font-size: 12px;">This is an automated email. Please do not reply.</p>
                </footer>
              </div>
            `,
            attachments: [
              {
                filename: "logo.png",
                path: 'assets/images/logo.png', // Replace with the correct logo path
                cid: "appLogo", // Attach logo as an inline image
              },
            ],
          };

          transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
              console.error("Failed to send email with login details:", err);
            } else {
              console.log("Email with login details sent:", info.response);
            }
          });
        }

        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
          expiresIn: "1h",
        });
        done(null, { token, profile });
      } catch (error) {
        console.error("Google login error:", error);
        done(error, null);
      }
    }
  )
);


// Passport session management
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(session({ secret: SESSION_SECRET, resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

// Login Success Page
app.get("/login-success", (req, res) => {
  const email = req.query.email;
  const clientIp = req.clientIp; // Get the client's IP address
  
  // Use ARP to resolve MAC address (only works in local network environments)
  exec(`arp -a ${clientIp}`, (err, stdout, stderr) => {
    if (err || stderr) {
      console.error("Error fetching MAC address:", err || stderr);
      res.status(500).send("Unable to fetch MAC address.");
      return;
    }

    // Parse MAC address from ARP output
    const macAddress = stdout.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/g);
    const mac = macAddress ? macAddress[0] : "Not available";
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Success</title>
        <script src="https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          body {
            font-family: 'Inter', Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
            color: #fff;
          }
          #particles-js {
            position: absolute;
            width: 100%;
            height: 100%;
            z-index: -1;
            background-color: #000; /* Black background theme */
          }
          .container {
            text-align: center;
            background: rgba(30, 30, 30, 0.9); /* Semi-transparent dark container */
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.5);
            max-width: 500px;
            width: 90%;
            animation: fadeIn 1.2s ease-out;
          }
          .logo {
            width: 120px;
            height: 120px;
            border-radius: 50%; /* Circular logo */
            margin-bottom: 20px;
            border: 3px solid #fff; /* Optional: white border for logo */
            object-fit: cover; /* Ensures the image fits within the circle */
          }
          h1 {
            color: #fff;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 20px;
          }
          p {
            color: #aaa;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 15px;
          }
          strong {
            color: #fff;
          }
          .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 25px;
            background-color: #1c3d5a;
            color: #ffffff;
            font-size: 16px;
            font-weight: 500;
            text-decoration: none;
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(28, 61, 90, 0.4);
            transition: background-color 0.3s, transform 0.2s, box-shadow 0.3s;
          }
          .btn:hover {
            background-color: #245b8a;
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(36, 91, 138, 0.5);
          }
          .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #666;
          }
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(-10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
        </style>
      </head>
      <body>
        <div id="particles-js"></div>
        <div class="container">
          <img src="/assets/images/logo.png" alt="App Logo" class="logo" />
          <h1>Check Your Google Mail!</h1>
          <p>An email has been sent to your Google account <strong>${email}</strong> with your login credentials.</p>
          <p>Please check your inbox to continue. If you haven't received the email, kindly check your spam folder or try again later.</p>
          <p>MAC Address: <strong>${mac}</strong></p>
          <a href="/" class="btn">Continue</a> <!-- Continue button that redirects to another page -->

          <div class="footer">&copy; 2024 Anatomy. All rights reserved.</div>
        </div>
        <script>
          // Particle.js configuration
          particlesJS("particles-js", {
            particles: {
              number: { value: 100, density: { enable: true, value_area: 800 } },
              color: { value: "#ffffff" }, /* White particles for contrast */
              shape: {
                type: "circle",
                stroke: { width: 0, color: "#000000" },
                polygon: { nb_sides: 5 }
              },
              opacity: {
                value: 0.5,
                random: false,
                anim: { enable: false, speed: 1, opacity_min: 0.1, sync: false }
              },
              size: {
                value: 5,
                random: true,
                anim: { enable: false, speed: 40, size_min: 0.1, sync: false }
              },
              line_linked: {
                enable: true,
                distance: 150,
                color: "#ffffff",
                opacity: 0.4,
                width: 1
              },
              move: {
                enable: true,
                speed: 6,
                direction: "none",
                random: false,
                straight: false,
                out_mode: "out",
                bounce: false,
                attract: { enable: false, rotateX: 600, rotateY: 1200 }
              }
            },
            interactivity: {
              detect_on: "canvas",
              events: {
                onhover: { enable: true, mode: "repulse" },
                onclick: { enable: true, mode: "push" },
                resize: true
              },
              modes: {
                grab: { distance: 400, line_linked: { opacity: 1 } },
                bubble: { distance: 400, size: 40, duration: 2, opacity: 8, speed: 3 },
                repulse: { distance: 200, duration: 0.4 },
                push: { particles_nb: 4 },
                remove: { particles_nb: 2 }
              }
            },
            retina_detect: true
          });
        </script>
      </body>
    </html>
    `);
  });
});







app.get("/auth/callback", passport.authenticate("google", { failureRedirect: "/" }), (req, res) => {
  const { token, profile } = req.user;

  // After the login, you can redirect to a success page
  res.redirect(`/login-success?email=${encodeURIComponent(profile.emails[0].value)}&token=${token}`);
});

// SMTP Configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SENDER_EMAIL,
    pass: process.env.SENDER_PASSWORD,
  },
});

// Test SMTP connection
transporter.verify((error, success) => {
  if (error) {
    console.error("SMTP connection failed:", error);
  } else {
    console.log("SMTP is connected successfully!");
    // Send an email when the server starts
    const logoPath = path.join(__dirname, "assets/images/logo.png");
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: process.env.RECIPIENT_EMAIL,
      subject: "Anatomy Server Started Successfully!",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; background-color: #f9f9f9;">
          <div style="text-align: center; margin-bottom: 20px;">
            <img src="cid:appLogo" alt="Anatomy Logo" style="max-width: 150px;" />
          </div>
          <h1 style="color: #333; text-align: center;">Anatomy Server Started Successfully!</h1>
          <p style="color: #555; font-size: 16px; line-height: 1.5;">
            Great news! Your Anatomy server has started successfully and is ready to serve your users.
          </p>
          <p style="color: #555; font-size: 16px; line-height: 1.5;">
            Server Details:
            <ul>
              <li><strong>IP Address:</strong> ${IP_ADDRESS}</li>
              <li><strong>Port:</strong> ${PORT}</li>
            </ul>
          </p>
          <div style="text-align: center; margin-top: 20px;">
            <a href="http://${IP_ADDRESS}:${PORT}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">Visit Server</a>
          </div>
          <footer style="background-color: #333; color: white; padding: 10px; text-align: center; margin-top: 20px;">
            <p style="font-size: 14px;">&copy; 2024 Anatomy. All Rights Reserved.</p>
            <p style="font-size: 12px;">This is an automated email. Please do not reply.</p>
          </footer>
        </div>
      `,
      attachments: [
        {
          filename: "logo.png",
          path: logoPath,
          cid: "appLogo",
        },
      ],
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("Failed to send startup email:", err);
      } else {
        console.log("Startup email sent:", info.response);
      }
    });
  }
});

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(passport.initialize());

// MongoDB Connection
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
};
connectToMongoDB();

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String }, // Removed unique constraint
});


const User = mongoose.model("User", userSchema);


// Signup Route
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required!" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User created successfully!" });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials!" });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    loggedInUserEmail = email;
    res.status(200).json({ message: "Login successful!", token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Send Quiz Completion Email Route
app.post("/send-quiz-completion-email", async (req, res) => {
  if (!loggedInUserEmail) {
    return res.status(401).json({ error: "No logged-in user to send the email to." });
  }

  const logoPath = path.join(__dirname, "assets/images/logo.png");
  const { score, incorrectLinks } = req.body;

  // Ensure score and links are being passed correctly
  if (score === undefined || !Array.isArray(incorrectLinks)) {
    return res.status(400).json({ error: "Invalid data format." });
  }

  // Build the incorrect answers HTML list
  const incorrectAnswersList = incorrectLinks
    .map(
      (link) =>
        `<li><a href="${link.link}" target="_blank">${link.question}</a></li>`
    )
    .join("");

  // Create the email content
  const mailOptions = {
    from: process.env.SENDER_EMAIL,
    to: loggedInUserEmail, // Use the logged-in user's email
    subject: "Quiz Completed!",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; background-color: #f9f9f9;">
        <div style="text-align: center; margin-bottom: 20px;">
          <img src="cid:appLogo" alt="Anatomy Logo" style="max-width: 150px;" />
        </div>
        <h1 style="color: #333; text-align: center;">Quiz Completed!</h1>
        <p style="color: #555; font-size: 16px; line-height: 1.5;">
          The quiz has been completed with a score of <strong>${score}</strong> out of 10.
        </p>
        <p style="color: #555; font-size: 16px; line-height: 1.5;">
          Here are the details of the quiz:
        </p>
        <ul style="color: #555; font-size: 16px;">
          <li><strong>Score:</strong> ${score} / 10</li>
          <li><strong>Incorrect Answers & Click To Research Them:</strong></li>
          <ul style="padding-left: 20px;">
            ${incorrectAnswersList}
          </ul>
        </ul>
        <div style="text-align: center; margin-top: 20px;">
          <a href="http://www.yourcompany.com" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">Visit Anatomy</a>
        </div>
        <footer style="background-color: #333; color: white; padding: 10px; text-align: center; margin-top: 20px;">
          <p style="font-size: 14px;">&copy; 2024 Anatomy. All Rights Reserved.</p>
          <p style="font-size: 12px;">This is an automated email. Please do not reply.</p>
        </footer>
      </div>
    `,
    attachments: [
      {
        filename: "logo.png",
        path: logoPath,
        cid: "appLogo", // Attach logo as an inline image
      },
    ],
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Quiz completion email sent successfully!" });
  } catch (error) {
    console.error("Failed to send quiz completion email:", error);
    res.status(500).json({ error: "Failed to send email. Please try again later." });
  }
});

// Home route to show "Anatomy Server is live" message on webpage
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Anatomy Server</title>
      <script src="https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;700&display=swap');
        body {
          margin: 0;
          font-family: 'Montserrat', sans-serif;
          background-color: #1e1e2f;
          color: #e4e4e4;
          display: flex;
          flex-direction: column;
          min-height: 100vh;
          overflow-x: hidden;
          position: relative;
        }
        .particle-container {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          z-index: -1;
        }
        .dashboard-container {
          width: 90%;
          max-width: 1200px;
          padding: 30px;
          background-color: #2b2b3d;
          border-radius: 15px;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
          margin: 30px auto;
          flex-grow: 1;
          animation: fadeIn 1.2s ease-in-out;
          z-index: 1;
        }
        @keyframes fadeIn {
          0% { opacity: 0; transform: translateY(20px); }
          100% { opacity: 1; transform: translateY(0); }
        }
        .header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 30px;
        }
        .header img {
          height: 100px;
          width: 100px;
          border-radius: 50%;
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .header h1 {
          font-size: 36px;
          color: #fff;
          font-weight: 700;
          margin: 0;
        }
        .header p {
  font-size: 18px;
  color: #bbb;
  margin-top: 5px;
  text-align: center; /* Center the text */
}

        .main-content {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 30px;
          margin-bottom: 40px;
        }
        .cards {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }
        .card {
          background: linear-gradient(145deg, #3b3b4f, #242435);
          padding: 20px;
          border-radius: 10px;
          box-shadow: inset 0 4px 8px rgba(0, 0, 0, 0.3), 0 5px 15px rgba(0, 0, 0, 0.3);
          transition: transform 0.3s ease, box-shadow 0.3s ease;
          border-left: 5px solid #ff7f50;
        }
        .card:hover {
          transform: translateY(-5px) scale(1.02);
          box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
        }
        .card h3 {
          font-size: 24px;
          color: #ffcc00;
          margin-bottom: 10px;
        }
        .card p {
          font-size: 16px;
          color: #ddd;
        }
        .recent-activities {
          background: linear-gradient(145deg, #41415b, #2c2c3d);
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .recent-activities h2 {
          font-size: 28px;
          margin-bottom: 15px;
          color: #ffcc00;
        }
        .recent-activities ul {
          padding-left: 20px;
        }
        .recent-activities li {
          font-size: 16px;
          color: #ddd;
          margin-bottom: 10px;
        }
        .statistics {
          display: flex;
          justify-content: space-between;
          gap: 30px;
          margin-top: 40px;
        }
        .stat-card {
          background: linear-gradient(145deg, #41415b, #2c2c3d);
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
          width: 30%;
          text-align: center;
        }
        .stat-card h3 {
          font-size: 30px;
          color: #ffcc00;
        }
        .stat-card p {
          font-size: 16px;
          color: #ddd;
        }
        .team-section {
          margin-top: 40px;
          display: flex;
          justify-content: space-around;
          gap: 20px;
        }
        .team-member {
          background: linear-gradient(145deg, #3b3b4f, #242435);
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
          text-align: center;
          width: 200px;
        }
        .team-member img {
          border-radius: 50%;
          width: 80px;
          height: 80px;
          margin-bottom: 15px;
        }
        .team-member h4 {
          color: #ffcc00;
          font-size: 20px;
          margin-bottom: 10px;
        }
        .team-member p {
          color: #ddd;
          font-size: 16px;
        }
        footer {
          background-color: #282836;
          color: #999;
          padding: 20px;
          text-align: center;
          font-size: 14px;
          border-top: 2px solid #444;
        }
        footer p {
          margin: 0;
        }
        footer a {
          color: #ff7f50;
          text-decoration: none;
          font-weight: 500;
        }
      </style>
    </head>
    <body>
      <div id="particle-container" class="particle-container"></div>
      <div class="dashboard-container">
        <div class="header">
          <img src="/assets/images/logo.png" alt="App Logo" />
          <div>
            <h1>Anatomy Server Dashboard</h1>
            <p>3D Virtually Perfect</p>
          </div>
        </div>
        <div class="main-content">
          <div class="cards">
            <div class="card">
              <h3>User Engagement</h3>
              <p>Track user activities in real-time and analyze trends.</p>
            </div>
            <div class="card">
              <h3>Performance</h3>
              <p>Analyze performance metrics and improve efficiency.</p>
            </div>
          </div>
          <div class="recent-activities">
            <h2>Recent Activities</h2>
            <ul>
              <li>Updated privacy policy on 1st Dec 2024</li>
              <li>New feature "Dark Mode" released</li>
              <li>Performance optimization completed</li>
            </ul>
          </div>
        </div>
        <div class="statistics">
          <div class="stat-card">
            <h3>Users</h3>
            <p>10,000</p>
          </div>
          <div class="stat-card">
            <h3>Active Users</h3>
            <p>7,500</p>
          </div>
          <div class="stat-card">
            <h3>Total Revenue</h3>
            <p>$50,000</p>
          </div>
        </div>
        <div class="team-section">
          <div class="team-member">
            <img src="https://png.pngtree.com/png-clipart/20190520/original/pngtree-vector-users-icon-png-image_4144740.jpg" alt="Team Member 1">
            <h4>Muhammad Ahsan</h4>
            <p>Backend Developer</p>
          </div>
          <div class="team-member">
            <img src="https://png.pngtree.com/png-clipart/20190520/original/pngtree-vector-users-icon-png-image_4144740.jpg" alt="Team Member 2">
            <h4>Huzaifa</h4>
            <p>UI/UX Designer</p>
          </div>
          <div class="team-member">
            <img src="https://png.pngtree.com/png-clipart/20190520/original/pngtree-vector-users-icon-png-image_4144740.jpg" alt="Team Member 3">
            <h4>Ahmed</h4>
            <p>Project Manager</p>
          </div>
        </div>
        <footer>
          <p>&copy; 2024 Anatomy. All rights reserved. <a href="#">Terms</a> | <a href="#">Privacy Policy</a></p>
        </footer>
      </div>
      <script>
        particlesJS("particle-container", {
          particles: {
            number: { value: 80, density: { enable: true, value_area: 800 } },
            shape: { type: "circle" },
            opacity: { value: 0.5 },
            size: { value: 3 },
            line_linked: { enable: true, color: "#fff", opacity: 0.5, width: 2 },
          },
          interactivity: {
            events: {
              onhover: { enable: true, mode: "repulse" },
            },
          },
        });
      </script>
    </body>
    </html>
  `);
});




// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://${IP_ADDRESS}:${PORT}`);
});


