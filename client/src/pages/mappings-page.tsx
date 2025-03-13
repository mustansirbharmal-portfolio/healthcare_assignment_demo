import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import MainLayout from "@/components/layout/main-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue 
} from "@/components/ui/select";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import AddMappingDialog from "@/components/add-mapping-dialog";
import { useLocation } from "wouter";

interface Mapping {
  id: number;
  patientId: number;
  doctorId: number;
  status: string;
  notes?: string;
  assignedDate: string;
  lastVisit?: string;
  patient?: {
    firstName: string;
    lastName: string;
  };
  doctor?: {
    firstName: string;
    lastName: string;
    specialty: string;
  };
}

export default function MappingsPage() {
  const [isAddMappingOpen, setIsAddMappingOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const { toast } = useToast();
  const [, navigate] = useLocation();

  const { data: mappings = [], isLoading } = useQuery<Mapping[]>({
    queryKey: ['/api/mappings'],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/mappings");
      return res.json();
    }
  });

  const deleteMappingMutation = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/mappings/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Mapping deleted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/mappings'] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: `Failed to delete mapping: ${error.message}`,
        variant: "destructive",
      });
    }
  });

  // Filter mappings based on search term and status
  const filteredMappings = mappings.filter(mapping => {
    const patientName = `${mapping.patient?.firstName} ${mapping.patient?.lastName}`.toLowerCase();
    const doctorName = `${mapping.doctor?.firstName} ${mapping.doctor?.lastName}`.toLowerCase();

    const matchesSearch = 
      patientName.includes(searchTerm.toLowerCase()) || 
      doctorName.includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === "all" || mapping.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const handleDeleteMapping = (id: number) => {
    if (confirm("Are you sure you want to delete this mapping?")) {
      deleteMappingMutation.mutate(id);
    }
  };

  return (
    <MainLayout>
      <div className="container mx-auto py-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Patient-Doctor Mappings</h1>
          <Button onClick={() => setIsAddMappingOpen(true)}>Assign Doctor</Button>
        </div>

        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="col-span-2">
              <Input
                placeholder="Search by patient or doctor name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <div>
              <Select
                value={statusFilter}
                onValueChange={setStatusFilter}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="Active">Active</SelectItem>
                  <SelectItem value="Pending">Pending</SelectItem>
                  <SelectItem value="Completed">Completed</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          </div>
        ) : filteredMappings.length === 0 ? (
          <div className="text-center py-12">
            <h2 className="text-xl font-medium text-gray-500">No mappings found</h2>
            <p className="mt-2 text-gray-400">Try adjusting your search or filters, or assign a doctor to a patient</p>
          </div>
        ) : (
          <div className="bg-white shadow rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Patient</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Doctor</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assigned Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Visit</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredMappings.map((mapping) => (
                  <tr key={mapping.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10 bg-gray-200 rounded-full flex items-center justify-center">
                          <span className="text-gray-500 font-medium">
                            {mapping.patient?.firstName?.charAt(0) || ''}
                            {mapping.patient?.lastName?.charAt(0) || ''}
                          </span>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            {mapping.patient?.firstName} {mapping.patient?.lastName}
                          </div>
                          <Button
                            variant="link"
                            className="p-0 h-auto text-sm text-primary"
                            onClick={() => navigate(`/patients/${mapping.patientId}`)}
                          >
                            View Patient
                          </Button>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10 bg-gray-200 rounded-full flex items-center justify-center">
                          <span className="text-gray-500 font-medium">
                            {mapping.doctor?.firstName?.charAt(0) || ''}
                            {mapping.doctor?.lastName?.charAt(0) || ''}
                          </span>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            Dr. {mapping.doctor?.firstName} {mapping.doctor?.lastName}
                          </div>
                          <div className="text-sm text-gray-500">
                            {mapping.doctor?.specialty}
                          </div>
                          <Button
                            variant="link"
                            className="p-0 h-auto text-sm text-primary"
                            onClick={() => navigate(`/doctors/${mapping.doctorId}`)}
                          >
                            View Doctor
                          </Button>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                        ${mapping.status === 'Active' ? 'bg-green-100 text-green-800' : 
                          mapping.status === 'Pending' ? 'bg-yellow-100 text-yellow-800' : 
                          'bg-blue-100 text-blue-800'}`}>
                        {mapping.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(mapping.assignedDate).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {mapping.lastVisit ? new Date(mapping.lastVisit).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDeleteMapping(mapping.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <AddMappingDialog
        open={isAddMappingOpen}
        onOpenChange={setIsAddMappingOpen}
      />
    </MainLayout>
  );
}