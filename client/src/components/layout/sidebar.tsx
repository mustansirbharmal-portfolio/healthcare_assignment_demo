import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/use-auth";

interface NavItemProps {
  icon: string;
  label: string;
  href: string;
  isActive: boolean;
}

const NavItem = ({ icon, label, href, isActive }: NavItemProps) => {
  const baseClass = "flex items-center px-4 py-3 hover:bg-primary-700 hover:text-white";
  const activeClass = "text-white bg-primary-600";
  const inactiveClass = "text-gray-300";

  return (
    <Link href={href} className={cn(baseClass, isActive ? activeClass : inactiveClass)}>
      <i className={`${icon} mr-3`}></i>
      <span>{label}</span>
    </Link>
  );
};

export default function Sidebar() {
  const [location] = useLocation();
  const { logoutMutation } = useAuth();

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  return (
    <div className="bg-[#212529] text-white w-full md:w-64 flex-shrink-0 md:flex flex-col hidden">
      <div className="p-4 flex items-center justify-center border-b border-gray-700">
        <i className="ri-heart-pulse-fill text-2xl text-primary-500 mr-2"></i>
        <h1 className="text-xl font-semibold">HealthCare Hub</h1>
      </div>
      
      <nav className="flex-1 overflow-y-auto py-4">
        <div className="px-4 mb-3 text-gray-400 uppercase text-xs font-semibold">Main</div>
        <NavItem 
          icon="ri-dashboard-line" 
          label="Dashboard" 
          href="/" 
          isActive={location === '/'} 
        />
        
        <div className="px-4 mb-3 mt-6 text-gray-400 uppercase text-xs font-semibold">Management</div>
        <NavItem 
          icon="ri-user-heart-line" 
          label="Patients" 
          href="/patients" 
          isActive={location === '/patients'} 
        />
        <NavItem 
          icon="ri-mental-health-line" 
          label="Doctors" 
          href="/doctors" 
          isActive={location === '/doctors'} 
        />
        <NavItem 
          icon="ri-link" 
          label="Assignments" 
          href="/mappings" 
          isActive={location === '/mappings'} 
        />
        
        <div className="px-4 mb-3 mt-6 text-gray-400 uppercase text-xs font-semibold">Account</div>
        <NavItem 
          icon="ri-user-settings-line" 
          label="Profile" 
          href="/profile" 
          isActive={location === '/profile'} 
        />
        <a 
          onClick={handleLogout} 
          className="flex items-center px-4 py-3 text-gray-300 hover:bg-primary-700 hover:text-white cursor-pointer"
        >
          <i className="ri-logout-box-line mr-3"></i>
          <span>Logout</span>
        </a>
      </nav>
    </div>
  );
}
