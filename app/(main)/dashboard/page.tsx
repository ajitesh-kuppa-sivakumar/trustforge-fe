"use client";

import { useEffect, useState } from "react";
import { useRecoilValue } from "recoil";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Shield,
  Upload,
  AlertTriangle,
  CheckCircle,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { authState } from "@/lib/atoms";
import { dashboard } from "@/lib/api";
import { useRouter } from "next/navigation";

interface DashboardStats {
  totalScans: number;
  completedScans: number;
  failedScans: number;
  averageTFScore: number;
  scansByStatus: {
    completed: number;
    failed: number;
  };
  topVulnerabilities: Record<string, number>;
  scanTrends: Record<string, number>;
  averageScanDuration: number;
  successRate: number;
  severityDistribution: {
    high: number;
    medium: number;
    low: number;
  };
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const auth = useRecoilValue(authState);
  const router = useRouter();

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await dashboard.getStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to load dashboard stats:", error);
      } finally {
        setIsLoading(false);
      }
    };

    loadStats();
  }, []);

  const StatCard = ({ icon: Icon, title, value, description }: any) => (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">
          {isLoading ? <Skeleton className="h-8 w-20" /> : value}
        </div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );

  const scanTrendsData = stats?.scanTrends
    ? Object.entries(stats.scanTrends).map(([date, count]) => ({
        date,
        scans: count,
      }))
    : [];

  return (
    <div className="min-h-screen bg-background">
      <div className="flex flex-col">
        <div className="flex-1 space-y-4 p-8 pt-6">
          <div className="flex items-center justify-between space-y-2">
            <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
            <Button onClick={() => router.push("/scan")}>
              <Upload className="mr-2 h-4 w-4" />
              New Scan
            </Button>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <StatCard
              icon={Activity}
              title="Total Scans"
              value={stats?.totalScans}
              description="All-time scans performed"
            />
            <StatCard
              icon={CheckCircle}
              title="Success Rate"
              value={`${stats?.successRate}%`}
              description="Scan completion rate"
            />
            <StatCard
              icon={AlertTriangle}
              title="Critical Findings"
              value={stats?.severityDistribution.high}
              description="High severity vulnerabilities"
            />
            <StatCard
              icon={Activity}
              title="Average TF Score"
              value={stats?.averageTFScore}
              description="Trust Forge Score"
            />
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-4">
              <CardHeader>
                <CardTitle>Scan Activity</CardTitle>
              </CardHeader>
              <CardContent className="pl-2">
                <ResponsiveContainer width="100%" height={350}>
                  <BarChart data={scanTrendsData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="scans" fill="hsl(var(--primary))" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="col-span-3">
              <CardHeader>
                <CardTitle>Security Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="mt-2 space-y-8">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        <span className="font-medium">Trust Factor Score</span>
                      </div>
                      <span>{stats?.averageTFScore}/100</span>
                    </div>
                    <Progress value={stats?.averageTFScore || 0} />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
