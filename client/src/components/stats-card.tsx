import { Card, CardContent } from "@/components/ui/card";

type StatsCardProps = {
  icon: string;
  iconColor: "blue" | "green" | "purple" | "yellow" | "red";
  title: string;
  value: number;
};

const iconColorMap = {
  blue: "bg-blue-100 text-blue-500",
  green: "bg-green-100 text-green-500",
  purple: "bg-purple-100 text-purple-500",
  yellow: "bg-yellow-100 text-yellow-500",
  red: "bg-red-100 text-red-500",
};

export default function StatsCard({ icon, iconColor, title, value }: StatsCardProps) {
  return (
    <Card>
      <CardContent className="p-4 flex items-center">
        <div className={`rounded-full ${iconColorMap[iconColor]} p-3 mr-4`}>
          <i className={`${icon} text-xl`}></i>
        </div>
        <div>
          <h3 className="text-lg font-semibold text-gray-700">{value}</h3>
          <p className="text-gray-500 text-sm">{title}</p>
        </div>
      </CardContent>
    </Card>
  );
}
