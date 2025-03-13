import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { AuthProvider } from "@/hooks/use-auth";
import NotFound from "@/pages/not-found";
import AuthPage from "@/pages/auth-page";
import DashboardPage from "@/pages/dashboard-page";
import PatientsPage from "@/pages/patients-page";
import DoctorsPage from "@/pages/doctors-page";
import MappingsPage from "@/pages/mappings-page";
import { ProtectedRoute } from "./lib/protected-route";
import DoctorDetailsPage from "@/pages/doctor-details-page";
import EditDoctorPage from "@/pages/edit-doctor-page";
import PatientDetailsPage from "@/pages/patient-details-page";
import PatientEditPage from "@/pages/patient-edit-page";

function Router() {
  return (
    <Switch>
      <Route path="/auth" component={AuthPage} />
      <ProtectedRoute path="/" component={DashboardPage} />
      <ProtectedRoute path="/patients" component={PatientsPage} />
      <ProtectedRoute path="/patients/:id" component={PatientDetailsPage} />
      <ProtectedRoute path="/patients/edit/:id" component={PatientEditPage} />
      <ProtectedRoute path="/doctors" component={DoctorsPage} />
      <ProtectedRoute path="/doctors/:id" component={DoctorDetailsPage} />
      <ProtectedRoute path="/doctors/edit/:id" component={EditDoctorPage} />
      <ProtectedRoute path="/mappings" component={MappingsPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;