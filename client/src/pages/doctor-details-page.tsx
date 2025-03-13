import { useState, useEffect } from "react";
import { useParams, useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import MainLayout from "@/components/layout/main-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Doctor } from "@shared/schema";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

export default function DoctorDetailsPage() {
  const { id } = useParams();
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  const { data: doctor, isLoading } = useQuery<Doctor>({
    queryKey: [`/api/doctors/${id}`],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/doctors/${id}`);
      return res.json();
    }
  });

  const deleteDoctorMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/doctors/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Doctor deleted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/doctors'] });
      navigate("/doctors");
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: `Failed to delete doctor: ${error.message}`,
        variant: "destructive",
      });
    }
  });

  if (isLoading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
        </div>
      </MainLayout>
    );
  }

  if (!doctor) {
    return (
      <MainLayout>
        <div className="flex flex-col items-center justify-center h-full">
          <h2 className="text-2xl font-bold mb-4">Doctor Not Found</h2>
          <Button onClick={() => navigate("/doctors")}>Back to Doctors</Button>
        </div>
      </MainLayout>
    );
  }

  const handleDelete = () => {
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    deleteDoctorMutation.mutate();
    setDeleteDialogOpen(false);
  };

  return (
    <MainLayout>
      <div className="container mx-auto py-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Doctor Details</h1>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => navigate("/doctors")}>
              Back
            </Button>
            <Button 
              variant="default" 
              onClick={() => navigate(`/doctors/edit/${id}`)}
            >
              Edit
            </Button>
            <Button 
              variant="destructive" 
              onClick={handleDelete}
            >
              Delete
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle>Profile</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col space-y-4">
                <div className="w-32 h-32 mx-auto bg-gray-200 rounded-full flex items-center justify-center text-gray-500 text-4xl">
                  {doctor.firstName?.charAt(0) || ''}{doctor.lastName?.charAt(0) || ''}
                </div>
                <h2 className="text-2xl font-bold text-center">
                  Dr. {doctor.firstName} {doctor.lastName}
                </h2>
                <p className="text-muted-foreground text-center">{doctor.specialty}</p>
                <div className="pt-4 border-t">
                  <div className="grid grid-cols-2 gap-y-2">
                    <span className="text-sm text-muted-foreground">Email:</span>
                    <span className="text-sm">{doctor.email}</span>
                    <span className="text-sm text-muted-foreground">Phone:</span>
                    <span className="text-sm">{doctor.phone}</span>
                    <span className="text-sm text-muted-foreground">License No:</span>
                    <span className="text-sm">{doctor.licenseNumber}</span>
                    <span className="text-sm text-muted-foreground">Status:</span>
                    <span className="text-sm capitalize">{doctor.status}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <Tabs defaultValue="info">
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle>Doctor Information</CardTitle>
                  <TabsList>
                    <TabsTrigger value="info">Bio</TabsTrigger>
                    <TabsTrigger value="schedule">Schedule</TabsTrigger>
                    <TabsTrigger value="patients">Patients</TabsTrigger>
                  </TabsList>
                </div>
              </CardHeader>
              <CardContent>
                <TabsContent value="info" className="m-0">
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-medium mb-2">About</h3>
                      <p className="text-muted-foreground">
                        {doctor.bio || "No bio information available."}
                      </p>
                    </div>
                    <div>
                      <h3 className="text-lg font-medium mb-2">Education</h3>
                      <p className="text-muted-foreground">
                        {doctor.education || "No education information available."}
                      </p>
                    </div>
                    <div>
                      <h3 className="text-lg font-medium mb-2">Experience</h3>
                      <p className="text-muted-foreground">
                        {doctor.yearsOfExperience} years of experience in {doctor.specialty}
                      </p>
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="schedule" className="m-0">
                  <div className="space-y-4">
                    <h3 className="text-lg font-medium mb-2">Working Hours</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-muted p-4 rounded-lg">
                        <h4 className="text-sm font-medium mb-2">Weekdays</h4>
                        <p className="text-muted-foreground">9:00 AM - 5:00 PM</p>
                      </div>
                      <div className="bg-muted p-4 rounded-lg">
                        <h4 className="text-sm font-medium mb-2">Weekends</h4>
                        <p className="text-muted-foreground">By appointment only</p>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mt-4">
                      Note: Schedule information is static. In a production application, 
                      this would be dynamically fetched from the database.
                    </p>
                  </div>
                </TabsContent>
                <TabsContent value="patients" className="m-0">
                  <div className="space-y-4">
                    <h3 className="text-lg font-medium mb-2">Patient Records</h3>
                    <p className="text-muted-foreground">
                      This feature is not yet implemented. In a production application,
                      this would show a list of patients assigned to this doctor.
                    </p>
                  </div>
                </TabsContent>
              </CardContent>
            </Tabs>
          </Card>
        </div>
      </div>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete Dr. {doctor.firstName} {doctor.lastName}'s
              record and all associated data from the database.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDelete}>
              {deleteDoctorMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </MainLayout>
  );
}