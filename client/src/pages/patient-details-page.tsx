import { useState, useEffect } from "react";
import { useParams, useLocation, Link } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import MainLayout from "@/components/layout/main-layout";
import { Patient, Doctor, PatientDoctorMapping } from "@shared/schema";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";

export default function PatientDetailsPage() {
  const { id } = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);

  const { data: patient, isLoading, error } = useQuery<Patient>({
    queryKey: [`/api/patients/${id}`],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/patients/${id}`);
      return res.json();
    },
    enabled: !!id
  });

  const { data: mappings = [] } = useQuery<PatientDoctorMapping[]>({
    queryKey: [`/api/mappings/${id}`],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/mappings/${id}`);
      return res.json();
    },
    enabled: !!id
  });

  const { data: doctors = [] } = useQuery<Doctor[]>({
    queryKey: ['/api/doctors'],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/doctors");
      return res.json();
    },
    enabled: !!id
  });

  // Get doctor details for each mapping
  const assignedDoctors = mappings.map(mapping => {
    const doctor = doctors.find(d => d.id === mapping.doctorId);
    return { ...mapping, doctor };
  });

  const deletePatientMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/patients/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Patient deleted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/patients'] });
      navigate("/patients");
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: `Failed to delete patient: ${error.message}`,
        variant: "destructive",
      });
    }
  });

  if (isLoading) {
    return (
      <MainLayout>
        <div className="container mx-auto py-6">
          <div className="bg-white shadow rounded-lg p-6">
            <Skeleton className="h-8 w-64 mb-4" />
            <div className="space-y-4">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </div>
          </div>
        </div>
      </MainLayout>
    );
  }

  if (error || !patient) {
    return (
      <MainLayout>
        <div className="container mx-auto py-6">
          <div className="bg-white shadow rounded-lg p-6">
            <h1 className="text-xl font-semibold text-red-600">Error loading patient</h1>
            <p className="mt-2 text-gray-600">
              {error instanceof Error ? error.message : "Patient not found"}
            </p>
            <Button 
              className="mt-4" 
              variant="outline" 
              onClick={() => navigate("/patients")}
            >
              Back to Patients
            </Button>
          </div>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="container mx-auto py-6">
        <div className="mb-6 flex justify-between items-center">
          <Button 
            variant="outline" 
            onClick={() => navigate("/patients")}
            className="flex items-center"
          >
            <i className="ri-arrow-left-line mr-2"></i>
            Back to Patients
          </Button>
          <div className="space-x-2">
            <Button 
              variant="outline" 
              onClick={() => navigate(`/patients/edit/${id}`)}
              className="flex items-center"
            >
              <i className="ri-edit-line mr-2"></i>
              Edit
            </Button>
            <Button 
              variant="destructive" 
              onClick={() => setIsDeleteDialogOpen(true)}
              className="flex items-center"
            >
              <i className="ri-delete-bin-line mr-2"></i>
              Delete
            </Button>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex items-center">
              <div className="flex-shrink-0 h-16 w-16">
                <img 
                  className="h-16 w-16 rounded-full" 
                  src={`https://ui-avatars.com/api/?name=${encodeURIComponent(patient.firstName + ' ' + patient.lastName)}&background=random`} 
                  alt={`${patient.firstName} ${patient.lastName}`} 
                />
              </div>
              <div className="ml-4">
                <h1 className="text-2xl font-bold text-gray-900">
                  {patient.firstName} {patient.lastName}
                </h1>
                <span className={`mt-1 px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                  patient.status === 'Active' ? 'bg-green-100 text-green-800' :
                  patient.status === 'Pending' ? 'bg-yellow-100 text-yellow-800' :
                  patient.status === 'Critical' ? 'bg-red-100 text-red-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {patient.status}
                </span>
              </div>
            </div>
          </div>

          <div className="px-6 py-4">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Patient Information</h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-sm font-medium text-gray-500">Personal Details</h3>
                <div className="mt-2 space-y-3">
                  <div>
                    <span className="text-sm text-gray-500">Age:</span>
                    <span className="ml-2 text-sm text-gray-900">{patient.age} years</span>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Gender:</span>
                    <span className="ml-2 text-sm text-gray-900">{patient.gender}</span>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">ID:</span>
                    <span className="ml-2 text-sm text-gray-900">#{patient.id}</span>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-gray-500">Contact Information</h3>
                <div className="mt-2 space-y-3">
                  <div>
                    <span className="text-sm text-gray-500">Email:</span>
                    <span className="ml-2 text-sm text-gray-900">{patient.email}</span>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Phone:</span>
                    <span className="ml-2 text-sm text-gray-900">{patient.phone}</span>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Last Visit:</span>
                    <span className="ml-2 text-sm text-gray-900">
                      {patient.lastVisit ? new Date(patient.lastVisit).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Assigned Doctors Section */}
            <div className="bg-white shadow rounded-lg p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Assigned Doctors</h2>

              {assignedDoctors.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {assignedDoctors.map((mapping) => (
                    <div key={mapping.id} className="border rounded-lg p-4 flex items-start">
                      <div className="flex-shrink-0 h-12 w-12 bg-gray-200 rounded-full flex items-center justify-center text-gray-600 mr-4">
                        {mapping.doctor?.firstName?.charAt(0) || ''}{mapping.doctor?.lastName?.charAt(0) || ''}
                      </div>
                      <div>
                        <h3 className="text-lg font-medium">
                          Dr. {mapping.doctor?.firstName} {mapping.doctor?.lastName}
                        </h3>
                        <p className="text-sm text-gray-500">{mapping.doctor?.specialty}</p>
                        <div className="mt-1">
                          <span className={`px-2 py-1 inline-flex text-xs leading-4 font-semibold rounded-full ${
                            mapping.status === 'Active' ? 'bg-green-100 text-green-800' :
                            mapping.status === 'Pending' ? 'bg-yellow-100 text-yellow-800' :
                            mapping.status === 'Completed' ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {mapping.status}
                          </span>
                        </div>
                        {mapping.notes && (
                          <p className="mt-2 text-sm">
                            <span className="font-medium">Notes:</span> {mapping.notes}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6 bg-gray-50 rounded-lg">
                  <p className="text-gray-500">No doctors assigned to this patient</p>
                  <Link href="/mappings">
                    <Button variant="link" className="mt-2">
                      Assign a doctor
                    </Button>
                  </Link>
                </div>
              )}
            </div>

            {patient.medicalNotes && (
              <div className="mt-6">
                <h3 className="text-sm font-medium text-gray-500">Medical Notes</h3>
                <div className="mt-2 p-3 bg-gray-50 rounded-md text-sm text-gray-900">
                  {patient.medicalNotes}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <AlertDialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete the patient
              record and any associated data.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction 
              onClick={() => deletePatientMutation.mutate()}
              className="bg-red-600 hover:bg-red-700"
            >
              {deletePatientMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </MainLayout>
  );
}