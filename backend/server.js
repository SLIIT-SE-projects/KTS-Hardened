const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const connectDb = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const managerRoutes = require("./routes/managerRoutes");
const employeeRoutes = require("./routes/employeeRoutes");
const busRoutes = require("./routes/busRoutes");
const roadRouteRoutes = require("./routes/roadRouteRoutes");
const errorHandler = require("./middleware/errorMiddleware");
const ticketRoutes = require("./routes/ticketRoutes");
const defaultLimiter = require("./middleware/rateLimit");

//middleware
const morgan = require("morgan");
const app = express();

// Parse trusted origins from environment variable
const originsString = process.env.TRUSTED_ORIGINS;
const trustedOrigins = originsString ? originsString.split(',') : [];

console.log('trustedOrigins :>> ', trustedOrigins);

// Configure CORS
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    // or any request from a trusted origin
    if (!origin || trustedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
};

//middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: "50mb" }));
app.use(morgan("dev"));

// --- Rate limiting ---
// Global default for all routes
app.use(defaultLimiter);

//routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/managers", managerRoutes);
app.use("/api/employees", employeeRoutes);
app.use("/api/buses", busRoutes);
app.use("/api/roadRoutes", roadRouteRoutes);
app.use("/api/tickets", ticketRoutes);

//ERROR Middleware
app.use(errorHandler);

connectDb().then(async () => {
  app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
  });
});
