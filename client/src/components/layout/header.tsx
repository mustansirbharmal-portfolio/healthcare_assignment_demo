import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

interface HeaderProps {
  toggleSidebar: () => void;
}

export default function Header({ toggleSidebar }: HeaderProps) {
  const { user } = useAuth();
  const [hasNotifications] = useState(true);

  return (
    <header className="bg-white border-b border-gray-200 flex items-center justify-between px-4 py-3 h-16">
      <div className="flex items-center">
        <Button 
          variant="ghost" 
          size="icon"
          className="md:hidden text-gray-600 mr-4" 
          onClick={toggleSidebar}
        >
          <i className="ri-menu-line text-xl"></i>
        </Button>
        <div className="md:hidden flex items-center">
          <i className="ri-heart-pulse-fill text-xl text-primary-500 mr-2"></i>
          <h1 className="text-lg font-semibold">HealthCare Hub</h1>
        </div>
      </div>
      
      <div className="flex items-center space-x-4">
        <div className="relative">
          <Button variant="ghost" size="icon" className="text-gray-600">
            <i className="ri-notification-3-line text-xl"></i>
            {hasNotifications && (
              <span className="absolute top-0 right-0 h-2 w-2 rounded-full bg-red-500"></span>
            )}
          </Button>
        </div>
        
        <div className="flex items-center">
          <span className="mr-2 hidden md:inline-block">{user?.name}</span>
          <Avatar>
            <AvatarImage src={`https://ui-avatars.com/api/?name=${encodeURIComponent(user?.name || '')}&background=random`} />
            <AvatarFallback>{user?.name?.[0] || 'U'}</AvatarFallback>
          </Avatar>
        </div>
      </div>
    </header>
  );
}
