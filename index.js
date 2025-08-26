import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// Configure dotenv
dotenv.config();

console.log("JWT_SECRET:", process.env.JWT_SECRET);
console.log("CORS_ORIGIN:", process.env.CORS_ORIGIN);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;

// Security Middleware
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: [
          "'self'",
          "data:",
          "https:",
          "http://localhost:5173",
          "http://localhost:3000",
          "https://sowraashi-frontend.vercel.app",
        ],
      },
    },
  })
);

// Trust Proxy
app.set("trust proxy", 1);

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ✅ CORS Configuration
const corsOptions = {
  origin:
    process.env.NODE_ENV === "production"
      ? process.env.CORS_ORIGIN || "https://sowraashi-frontend.vercel.app"
      : ["http://localhost:3000", "http://localhost:5173"],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions)); // ✅ Apply globally

// Body parser
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static("public"));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, process.env.UPLOAD_PATH || "public/uploads/");
  },
  filename: function (req, file, cb) {
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(null, Date.now() + "-" + sanitizedName);
  },
});
const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/gif",
      "image/webp",
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

// Import routes
import authRoutes from "./routes/auth.js";
import productRoutes from "./routes/products.js";
import orderRoutes from "./routes/orders.js";

// Use routes
app.use("/api/auth", authRoutes);
app.use("/api/products", productRoutes);
app.use("/api/orders", orderRoutes);

// Serve uploaded files with CORS headers
app.use(
  "/uploads",
  (req, res, next) => {
    res.header(
      "Access-Control-Allow-Origin",
      process.env.NODE_ENV === "production"
        ? process.env.CORS_ORIGIN || "https://sowraashi-frontend.vercel.app"
        : "http://localhost:5173"
    );
    res.header("Access-Control-Allow-Methods", "GET");
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept"
    );
    next();
  },
  express.static(path.join(__dirname, "public/uploads"))
);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (process.env.NODE_ENV === "production") {
    res.status(500).json({
      message: "Internal server error",
      error: "Something went wrong. Please try again later.",
    });
  } else {
    res.status(500).json({
      message: "Internal server error",
      error: err.message,
      stack: err.stack,
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
