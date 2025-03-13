
import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { authenticateJWT, setupAuth } from "./auth";
import { 
  insertPatientSchema, 
  insertDoctorSchema, 
  insertMappingSchema 
} from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  // Set up authentication routes
  setupAuth(app);

  // Patient Management APIs
  // POST /api/patients – Add a new patient
  app.post("/api/patients", authenticateJWT, async (req, res, next) => {
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
        userId: req.user?.id as number
      });

      res.status(201).json(patient);
    } catch (error) {
      next(error);
    }
  });

  // GET /api/patients – Retrieve all patients created by the authenticated user
  app.get("/api/patients", authenticateJWT, async (req, res, next) => {
    try {
      const patients = await storage.getPatients(req.user?.id as number);
      res.json(patients);
    } catch (error) {
      next(error);
    }
  });

  // GET /api/patients/:id – Get details of a specific patient
  app.get("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }

      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if the patient belongs to the authenticated user
      if (patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to patient data" });
      }

      res.json(patient);
    } catch (error) {
      next(error);
    }
  });

  // PUT /api/patients/:id – Update patient details
  app.put("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }

      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if the patient belongs to the authenticated user
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

  // DELETE /api/patients/:id – Delete a patient
  app.delete("/api/patients/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }

      const patient = await storage.getPatient(id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if the patient belongs to the authenticated user
      if (patient.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to patient data" });
      }

      await storage.deletePatient(id);
      res.json({ message: "Patient deleted successfully" });
    } catch (error) {
      next(error);
    }
  });

  // Doctor Management APIs
  // POST /api/doctors – Add a new doctor
  app.post("/api/doctors", authenticateJWT, async (req, res, next) => {
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
        userId: req.user?.id as number
      });

      res.status(201).json(doctor);
    } catch (error) {
      next(error);
    }
  });

  // GET /api/doctors – Retrieve all doctors
  app.get("/api/doctors", authenticateJWT, async (req, res, next) => {
    try {
      const doctors = await storage.getDoctors(req.user?.id as number);
      res.json(doctors);
    } catch (error) {
      next(error);
    }
  });

  // GET /api/doctors/:id – Get details of a specific doctor
  app.get("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }

      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }

      // Check if the doctor belongs to the authenticated user
      if (doctor.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to doctor data" });
      }

      res.json(doctor);
    } catch (error) {
      next(error);
    }
  });

  // PUT /api/doctors/:id – Update doctor details
  app.put("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }

      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }

      // Check if the doctor belongs to the authenticated user
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

  // DELETE /api/doctors/:id – Delete a doctor
  app.delete("/api/doctors/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }

      const doctor = await storage.getDoctor(id);
      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }

      // Check if the doctor belongs to the authenticated user
      if (doctor.userId !== req.user?.id) {
        return res.status(403).json({ message: "Unauthorized access to doctor data" });
      }

      await storage.deleteDoctor(id);
      res.json({ message: "Doctor deleted successfully" });
    } catch (error) {
      next(error);
    }
  });

  // Patient-Doctor Mapping APIs
  // POST /api/mappings – Assign a doctor to a patient
  app.post("/api/mappings", authenticateJWT, async (req, res, next) => {
    try {
      const validationResult = insertMappingSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ 
          message: "Invalid mapping data", 
          errors: validationResult.error.errors 
        });
      }

      const mappingData = validationResult.data;
      
      // Verify that both patient and doctor exist and belong to this user
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

  // GET /api/mappings – Retrieve all mappings
  app.get("/api/mappings", authenticateJWT, async (req, res, next) => {
    try {
      const mappings = await storage.getMappings();
      res.json(mappings);
    } catch (error) {
      next(error);
    }
  });

  // GET /api/mappings/:patientId – Get doctors assigned to a patient
  app.get("/api/mappings/:patientId", authenticateJWT, async (req, res, next) => {
    try {
      const patientId = parseInt(req.params.patientId);
      if (isNaN(patientId)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }

      // Verify patient belongs to this user
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

  // DELETE /api/mappings/:id – Remove a doctor from a patient
  app.delete("/api/mappings/:id", authenticateJWT, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid mapping ID" });
      }

      const mapping = await storage.getMapping(id);
      if (!mapping) {
        return res.status(404).json({ message: "Mapping not found" });
      }

      // Verify that the patient in the mapping belongs to this user
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

  const httpServer = createServer(app);
  return httpServer;
}
