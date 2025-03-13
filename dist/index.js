// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/db.ts
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as dotenv from "dotenv";
dotenv.config();
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is not set");
}
var queryClient = postgres(process.env.DATABASE_URL);
var db = drizzle(queryClient);

// shared/schema.ts
import { pgTable, text, serial, integer, timestamp, unique } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true
});
var patients = pgTable("patients", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: text("email").notNull(),
  phone: text("phone").notNull(),
  age: integer("age").notNull(),
  gender: text("gender").notNull(),
  status: text("status").notNull(),
  medicalNotes: text("medical_notes"),
  lastVisit: timestamp("last_visit"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertPatientSchema = createInsertSchema(patients).omit({
  id: true,
  createdAt: true
});
var doctors = pgTable("doctors", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id),
  title: text("title").notNull(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  phone: text("phone").notNull(),
  specialty: text("specialty").notNull(),
  qualification: text("qualification").notNull(),
  status: text("status").notNull(),
  bio: text("bio"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertDoctorSchema = createInsertSchema(doctors).omit({
  id: true,
  createdAt: true
});
var patientDoctorMappings = pgTable("patient_doctor_mappings", {
  id: serial("id").primaryKey(),
  patientId: integer("patient_id").notNull().references(() => patients.id),
  doctorId: integer("doctor_id").notNull().references(() => doctors.id),
  status: text("status").notNull(),
  notes: text("notes"),
  assignedDate: timestamp("assigned_date").defaultNow().notNull(),
  lastVisit: timestamp("last_visit"),
  createdAt: timestamp("created_at").defaultNow().notNull()
}, (table) => {
  return {
    // Ensure a patient can be assigned to a doctor only once
    uniqueMapping: unique().on(table.patientId, table.doctorId)
  };
});
var insertMappingSchema = createInsertSchema(patientDoctorMappings).omit({
  id: true,
  assignedDate: true,
  createdAt: true
});
var loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6)
});
var patientWithDoctorsSchema = z.object({
  patient: z.object(createInsertSchema(patients).shape),
  doctors: z.array(z.object(createInsertSchema(doctors).shape)).optional()
});

// server/storage.ts
import { eq } from "drizzle-orm";
import session from "express-session";
import memorystore from "memorystore";
var MemoryStore = memorystore(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    this.sessionStore = new MemoryStore({
      checkPeriod: 864e5
      // prune expired entries every 24h
    });
  }
  // User operations
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async getUserByEmail(email) {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }
  async createUser(user) {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }
  // Patient operations
  async getPatient(id) {
    const [patient] = await db.select().from(patients).where(eq(patients.id, id));
    return patient;
  }
  async getPatients(userId) {
    return await db.select().from(patients).where(eq(patients.userId, userId));
  }
  async createPatient(patient) {
    const [newPatient] = await db.insert(patients).values(patient).returning();
    return newPatient;
  }
  async updatePatient(id, patient) {
    const [updatedPatient] = await db.update(patients).set(patient).where(eq(patients.id, id)).returning();
    return updatedPatient;
  }
  async deletePatient(id) {
    await db.delete(patientDoctorMappings).where(eq(patientDoctorMappings.patientId, id));
    const result = await db.delete(patients).where(eq(patients.id, id)).returning();
    return result.length > 0;
  }
  // Doctor operations
  async getDoctor(id) {
    const [doctor] = await db.select().from(doctors).where(eq(doctors.id, id));
    return doctor;
  }
  async getDoctors() {
    return await db.select().from(doctors);
  }
  async createDoctor(doctor) {
    const [newDoctor] = await db.insert(doctors).values(doctor).returning();
    return newDoctor;
  }
  async updateDoctor(id, doctor) {
    const [updatedDoctor] = await db.update(doctors).set(doctor).where(eq(doctors.id, id)).returning();
    return updatedDoctor;
  }
  async deleteDoctor(id) {
    await db.delete(patientDoctorMappings).where(eq(patientDoctorMappings.doctorId, id));
    const result = await db.delete(doctors).where(eq(doctors.id, id)).returning();
    return result.length > 0;
  }
  // Patient-Doctor Mapping operations
  async getMapping(id) {
    const [mapping] = await db.select().from(patientDoctorMappings).where(eq(patientDoctorMappings.id, id));
    return mapping;
  }
  async getMappings() {
    return await db.select().from(patientDoctorMappings);
  }
  async getMappingsByPatient(patientId) {
    return await db.select().from(patientDoctorMappings).where(eq(patientDoctorMappings.patientId, patientId));
  }
  async createMapping(mapping) {
    const [newMapping] = await db.insert(patientDoctorMappings).values(mapping).returning();
    return newMapping;
  }
  async deleteMapping(id) {
    const result = await db.delete(patientDoctorMappings).where(eq(patientDoctorMappings.id, id)).returning();
    return result.length > 0;
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import jwt from "jsonwebtoken";
var scryptAsync = promisify(scrypt);
var JWT_SECRET = process.env.JWT_SECRET || "healthcare-app-secret-key";
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
}
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      req.token = token;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1e3
      // 24 hours
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const user = await storage.getUserByEmail(email);
          if (!user || !await comparePasswords(password, user.password)) {
            return done(null, false, { message: "Invalid email or password" });
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
  app2.post("/api/auth/register", async (req, res, next) => {
    try {
      const userData = req.body;
      const existingUser = await storage.getUserByEmail(userData.email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }
      const hashedPassword = await hashPassword(userData.password);
      const user = await storage.createUser({
        ...userData,
        password: hashedPassword
      });
      const token = generateToken(user);
      req.login(user, (err) => {
        if (err) return next(err);
        const { password, ...userWithoutPassword } = user;
        res.status(201).json({
          ...userWithoutPassword,
          token
        });
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/auth/login", (req, res, next) => {
    try {
      const validationResult = loginSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid input",
          errors: validationResult.error.errors
        });
      }
      passport.authenticate("local", (err, user, info) => {
        if (err) return next(err);
        if (!user) {
          return res.status(401).json({ message: info?.message || "Authentication failed" });
        }
        req.login(user, (err2) => {
          if (err2) return next(err2);
          const token = generateToken(user);
          const { password, ...userWithoutPassword } = user;
          res.status(200).json({
            ...userWithoutPassword,
            token
          });
        });
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/auth/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.status(200).json({ message: "Successfully logged out" });
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { password, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
  });
}

// server/routes.ts
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.post("/api/patients", authenticateJWT, async (req, res, next) => {
    try {
      const validationResult = insertPatientSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid patient data",
          errors: validationResult.error.errors
        });
      }
      const patientData = validationResult.data;
      const patient = await storage.createPatient({
        ...patientData,
        userId: req.user?.id
      });
      res.status(201).json(patient);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/patients", authenticateJWT, async (req, res, next) => {
    try {
      const patients2 = await storage.getPatients(req.user?.id);
      res.json(patients2);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }
      if (patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to patient data" });
      }
      res.json(patient);
    } catch (error) {
      next(error);
    }
  });
  app2.put("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }
      if (patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to patient data" });
      }
      const validationResult = insertPatientSchema.partial().safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid patient data",
          errors: validationResult.error.errors
        });
      }
      const updatedPatient = await storage.updatePatient(id, validationResult.data);
      res.json(updatedPatient);
    } catch (error) {
      next(error);
    }
  });
  app2.delete("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }
      if (patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to patient data" });
      }
      await storage.deletePatient(id);
      res.json({ message: "Patient deleted successfully" });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/doctors", authenticateJWT, async (req, res, next) => {
    try {
      const validationResult = insertDoctorSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid doctor data",
          errors: validationResult.error.errors
        });
      }
      const doctorData = validationResult.data;
      const doctor = await storage.createDoctor({
        ...doctorData,
        userId: req.user?.id
      });
      res.status(201).json(doctor);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/doctors", authenticateJWT, async (req, res, next) => {
    try {
      const doctors2 = await storage.getDoctors(req.user?.id);
      res.json(doctors2);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }
      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }
      if (doctor.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to doctor data" });
      }
      res.json(doctor);
    } catch (error) {
      next(error);
    }
  });
  app2.put("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }
      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }
      if (doctor.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to doctor data" });
      }
      const validationResult = insertDoctorSchema.partial().safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid doctor data",
          errors: validationResult.error.errors
        });
      }
      const updatedDoctor = await storage.updateDoctor(id, validationResult.data);
      res.json(updatedDoctor);
    } catch (error) {
      next(error);
    }
  });
  app2.delete("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }
      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }
      if (doctor.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to doctor data" });
      }
      await storage.deleteDoctor(id);
      res.json({ message: "Doctor deleted successfully" });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/mappings", authenticateJWT, async (req, res, next) => {
    try {
      const validationResult = insertMappingSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          message: "Invalid mapping data",
          errors: validationResult.error.errors
        });
      }
      const mappingData = validationResult.data;
      const patient = await storage.getPatient(mappingData.patientId);
      if (!patient || patient.userId !== req.user?.id) {
        return res.status(404).json({ message: "Patient not found or unauthorized" });
      }
      const doctor = await storage.getDoctor(mappingData.doctorId);
      if (!doctor || doctor.userId !== req.user?.id) {
        return res.status(404).json({ message: "Doctor not found or unauthorized" });
      }
      const mapping = await storage.createMapping(mappingData);
      res.status(201).json(mapping);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/mappings", authenticateJWT, async (req, res, next) => {
    try {
      const mappings = await storage.getMappings();
      res.json(mappings);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/mappings/:patientId", authenticateJWT, async (req, res, next) => {
    try {
      const patientId = parseInt(req.params.patientId);
      if (isNaN(patientId)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      const patient = await storage.getPatient(patientId);
      if (!patient || patient.userId !== req.user?.id) {
        return res.status(404).json({ message: "Patient not found or unauthorized" });
      }
      const mappings = await storage.getMappingsByPatient(patientId);
      res.json(mappings);
    } catch (error) {
      next(error);
    }
  });
  app2.delete("/api/mappings/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid mapping ID" });
      }
      const mapping = await storage.getMapping(id);
      if (!mapping) {
        return res.status(404).json({ message: "Mapping not found" });
      }
      const patient = await storage.getPatient(mapping.patientId);
      if (!patient || patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to mapping data" });
      }
      await storage.deleteMapping(id);
      res.json({ message: "Mapping deleted successfully" });
    } catch (error) {
      next(error);
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client", "src"),
      "@shared": path.resolve(__dirname, "shared")
    }
  },
  root: path.resolve(__dirname, "client"),
  build: {
    outDir: path.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(__dirname2, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
