import { db, sql } from "./db";
import { 
  users, patients, doctors, patientDoctorMappings, 
  type User, type InsertUser, 
  type Patient, type InsertPatient,
  type Doctor, type InsertDoctor,
  type PatientDoctorMapping, type InsertPatientDoctorMapping
} from "@shared/schema";
import { eq, and } from "drizzle-orm";
import session from "express-session";
import memorystore from "memorystore";

const MemoryStore = memorystore(session);

export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Patient operations
  getPatient(id: number): Promise<Patient | undefined>;
  getPatients(userId: number): Promise<Patient[]>;
  createPatient(patient: InsertPatient): Promise<Patient>;
  updatePatient(id: number, patient: Partial<InsertPatient>): Promise<Patient | undefined>;
  deletePatient(id: number): Promise<boolean>;
  
  // Doctor operations
  getDoctor(id: number): Promise<Doctor | undefined>;
  getDoctors(): Promise<Doctor[]>;
  createDoctor(doctor: InsertDoctor): Promise<Doctor>;
  updateDoctor(id: number, doctor: Partial<InsertDoctor>): Promise<Doctor | undefined>;
  deleteDoctor(id: number): Promise<boolean>;
  
  // Patient-Doctor Mapping operations
  getMapping(id: number): Promise<PatientDoctorMapping | undefined>;
  getMappings(): Promise<PatientDoctorMapping[]>;
  getMappingsByPatient(patientId: number): Promise<PatientDoctorMapping[]>;
  createMapping(mapping: InsertPatientDoctorMapping): Promise<PatientDoctorMapping>;
  deleteMapping(id: number): Promise<boolean>;

  // Session store
  sessionStore: any; // Using any to avoid TypeScript errors with SessionStore
}

export class DatabaseStorage implements IStorage {
  sessionStore: any;

  constructor() {
    // Use in-memory store for sessions to avoid pg connection issues
    this.sessionStore = new MemoryStore({
      checkPeriod: 86400000 // prune expired entries every 24h
    });
  }

  // User operations
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  // Patient operations
  async getPatient(id: number): Promise<Patient | undefined> {
    const [patient] = await db.select().from(patients).where(eq(patients.id, id));
    return patient;
  }

  async getPatients(userId: number): Promise<Patient[]> {
    return await db.select().from(patients).where(eq(patients.userId, userId));
  }

  async createPatient(patient: InsertPatient): Promise<Patient> {
    const [newPatient] = await db.insert(patients).values(patient).returning();
    return newPatient;
  }

  async updatePatient(id: number, patient: Partial<InsertPatient>): Promise<Patient | undefined> {
    const [updatedPatient] = await db
      .update(patients)
      .set(patient)
      .where(eq(patients.id, id))
      .returning();
    return updatedPatient;
  }

  async deletePatient(id: number): Promise<boolean> {
    // First delete any mappings associated with this patient
    await db
      .delete(patientDoctorMappings)
      .where(eq(patientDoctorMappings.patientId, id));
    
    const result = await db
      .delete(patients)
      .where(eq(patients.id, id))
      .returning();
    
    return result.length > 0;
  }

  // Doctor operations
  async getDoctor(id: number): Promise<Doctor | undefined> {
    const [doctor] = await db.select().from(doctors).where(eq(doctors.id, id));
    return doctor;
  }

  async getDoctors(): Promise<Doctor[]> {
    return await db.select().from(doctors);
  }

  async createDoctor(doctor: InsertDoctor): Promise<Doctor> {
    const [newDoctor] = await db.insert(doctors).values(doctor).returning();
    return newDoctor;
  }

  async updateDoctor(id: number, doctor: Partial<InsertDoctor>): Promise<Doctor | undefined> {
    const [updatedDoctor] = await db
      .update(doctors)
      .set(doctor)
      .where(eq(doctors.id, id))
      .returning();
    return updatedDoctor;
  }

  async deleteDoctor(id: number): Promise<boolean> {
    // First delete any mappings associated with this doctor
    await db
      .delete(patientDoctorMappings)
      .where(eq(patientDoctorMappings.doctorId, id));
    
    const result = await db
      .delete(doctors)
      .where(eq(doctors.id, id))
      .returning();
    
    return result.length > 0;
  }

  // Patient-Doctor Mapping operations
  async getMapping(id: number): Promise<PatientDoctorMapping | undefined> {
    const [mapping] = await db
      .select()
      .from(patientDoctorMappings)
      .where(eq(patientDoctorMappings.id, id));
    return mapping;
  }

  async getMappings(): Promise<PatientDoctorMapping[]> {
    return await db.select().from(patientDoctorMappings);
  }

  async getMappingsByPatient(patientId: number): Promise<PatientDoctorMapping[]> {
    return await db
      .select()
      .from(patientDoctorMappings)
      .where(eq(patientDoctorMappings.patientId, patientId));
  }

  async createMapping(mapping: InsertPatientDoctorMapping): Promise<PatientDoctorMapping> {
    const [newMapping] = await db
      .insert(patientDoctorMappings)
      .values(mapping)
      .returning();
    return newMapping;
  }

  async deleteMapping(id: number): Promise<boolean> {
    const result = await db
      .delete(patientDoctorMappings)
      .where(eq(patientDoctorMappings.id, id))
      .returning();
    
    return result.length > 0;
  }
}

export const storage = new DatabaseStorage();
