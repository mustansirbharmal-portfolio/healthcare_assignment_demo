import { useQuery } from "@tanstack/react-query";
import MainLayout from "@/components/layout/main-layout";
import { useAuth } from "@/hooks/use-auth";
import StatsCard from "@/components/stats-card";
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";

export default function DashboardPage() {
  const { user } = useAuth();
  
  const { data: patients } = useQuery({
    queryKey: ['/api/patients'],
    staleTime: 30000,
  });
  
  const { data: doctors } = useQuery({
    queryKey: ['/api/doctors'],
    staleTime: 30000,
  });
  
  const { data: mappings } = useQuery({
    queryKey: ['/api/mappings'],
    staleTime: 30000,
  });

  const recentPatients = patients?.slice(0, 3) || [];
  const doctorAvailability = doctors?.slice(0, 4) || [];

  return (
    <MainLayout 
      title="Dashboard" 
      subtitle={`Welcome back, ${user?.name}`}
    >
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatsCard 
          icon="ri-user-heart-line" 
          iconColor="blue" 
          title="Total Patients" 
          value={patients?.length || 0} 
        />
        
        <StatsCard 
          icon="ri-mental-health-line" 
          iconColor="green" 
          title="Doctors" 
          value={doctors?.length || 0} 
        />
        
        <StatsCard 
          icon="ri-calendar-check-line" 
          iconColor="purple" 
          title="Today's Assignments" 
          value={mappings?.length || 0} 
        />
        
        <StatsCard 
          icon="ri-file-list-3-line" 
          iconColor="yellow" 
          title="Pending Tasks" 
          value={5} 
        />
      </div>
      
      {/* Recent Patients and Doctor Availability */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="px-4 py-3 border-b border-gray-200 flex justify-between items-center">
              <CardTitle className="text-lg font-semibold text-gray-800">Recent Patients</CardTitle>
              <a href="/patients" className="text-primary-500 text-sm hover:underline">View All</a>
            </CardHeader>
            
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Patient</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Doctor</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Visit</th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {recentPatients.length > 0 ? (
                    recentPatients.map((patient) => (
                      <tr key={patient.id}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-10 w-10">
                              <img className="h-10 w-10 rounded-full" src={`https://ui-avatars.com/api/?name=${encodeURIComponent(patient.firstName + ' ' + patient.lastName)}&background=random`} alt="Patient" />
                            </div>
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900">{patient.firstName} {patient.lastName}</div>
                              <div className="text-sm text-gray-500">#PT-{patient.id}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            patient.status === 'Active' ? 'bg-green-100 text-green-800' :
                            patient.status === 'Pending' ? 'bg-yellow-100 text-yellow-800' :
                            patient.status === 'Critical' ? 'bg-red-100 text-red-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {patient.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {/* This would need to be fetched from mappings */}
                          Assigned Doctor
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {patient.lastVisit ? new Date(patient.lastVisit).toLocaleDateString() : 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <a href={`/patients/${patient.id}`} className="text-primary-600 hover:text-primary-900 mr-3">View</a>
                          <a href={`/patients/edit/${patient.id}`} className="text-gray-600 hover:text-gray-900">Edit</a>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-4 text-center text-sm text-gray-500">
                        No patients found. <a href="/patients" className="text-primary-600 hover:underline">Add some patients</a>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
        
        <div>
          <Card className="mb-6">
            <CardHeader className="px-4 py-3 border-b border-gray-200">
              <CardTitle className="text-lg font-semibold text-gray-800">Doctor Availability</CardTitle>
            </CardHeader>
            
            <CardContent className="p-4">
              <ul className="space-y-3">
                {doctorAvailability.length > 0 ? (
                  doctorAvailability.map((doctor) => (
                    <li key={doctor.id} className="flex items-center justify-between">
                      <div className="flex items-center">
                        <img className="h-8 w-8 rounded-full mr-3" src={`https://ui-avatars.com/api/?name=${encodeURIComponent(doctor.name)}&background=random`} alt="Doctor" />
                        <span className="text-sm font-medium text-gray-900">{doctor.title} {doctor.name}</span>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        doctor.status === 'Available' ? 'bg-green-100 text-green-800' :
                        doctor.status === 'Busy' ? 'bg-red-100 text-red-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {doctor.status}
                      </span>
                    </li>
                  ))
                ) : (
                  <li className="text-center text-sm text-gray-500">
                    No doctors found. <a href="/doctors" className="text-primary-600 hover:underline">Add some doctors</a>
                  </li>
                )}
              </ul>
            </CardContent>
            
            <div className="px-4 py-3 bg-gray-50 text-right">
              <a href="/doctors" className="text-primary-500 text-sm hover:underline">View All Doctors</a>
            </div>
          </Card>
          
          {/* Recent Activity */}
          <Card>
            <CardHeader className="px-4 py-3 border-b border-gray-200">
              <CardTitle className="text-lg font-semibold text-gray-800">Recent Activity</CardTitle>
            </CardHeader>
            
            <CardContent className="p-4">
              <div className="flow-root">
                <ul className="-mb-8">
                  <li>
                    <div className="relative pb-8">
                      <span className="absolute top-5 left-5 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true"></span>
                      <div className="relative flex items-start space-x-3">
                        <div className="relative">
                          <div className="h-10 w-10 rounded-full bg-blue-500 flex items-center justify-center ring-8 ring-white">
                            <i className="ri-user-add-line text-white"></i>
                          </div>
                        </div>
                        <div className="min-w-0 flex-1">
                          <div>
                            <div className="text-sm text-gray-500">
                              <span className="font-medium text-gray-900">New patient</span> registered
                              <span className="whitespace-nowrap ml-2">1h ago</span>
                            </div>
                          </div>
                          <div className="mt-1 text-sm text-gray-700">
                            <p>Patient was added to the system</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                  
                  <li>
                    <div className="relative pb-8">
                      <span className="absolute top-5 left-5 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true"></span>
                      <div className="relative flex items-start space-x-3">
                        <div className="relative">
                          <div className="h-10 w-10 rounded-full bg-green-500 flex items-center justify-center ring-8 ring-white">
                            <i className="ri-link text-white"></i>
                          </div>
                        </div>
                        <div className="min-w-0 flex-1">
                          <div>
                            <div className="text-sm text-gray-500">
                              <span className="font-medium text-gray-900">Assignment</span> created
                              <span className="whitespace-nowrap ml-2">3h ago</span>
                            </div>
                          </div>
                          <div className="mt-1 text-sm text-gray-700">
                            <p>Doctor assigned to patient</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                  
                  <li>
                    <div className="relative">
                      <div className="relative flex items-start space-x-3">
                        <div className="relative">
                          <div className="h-10 w-10 rounded-full bg-yellow-500 flex items-center justify-center ring-8 ring-white">
                            <i className="ri-edit-line text-white"></i>
                          </div>
                        </div>
                        <div className="min-w-0 flex-1">
                          <div>
                            <div className="text-sm text-gray-500">
                              <span className="font-medium text-gray-900">Record</span> updated
                              <span className="whitespace-nowrap ml-2">6h ago</span>
                            </div>
                          </div>
                          <div className="mt-1 text-sm text-gray-700">
                            <p>Medical record was updated</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
