"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Upload,
  FileText,
  LogOut,
} from "lucide-react";
import { useRecoilValue } from "recoil";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { auth } from "@/lib/api";
import { authState } from "@/lib/atoms";
import Image from "next/image";

export function Sidebar() {
  const pathname = usePathname();
  const authData = useRecoilValue(authState);

  const navigation = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "Scan", href: "/scan", icon: Upload },
    { name: "Reports", href: "/reports", icon: FileText },
  ];

  return (
    <div className="flex h-screen flex-col border-r bg-card">
      <div className="p-6">
        <div className="flex items-center gap-2">
          {/* <Shield className="h-6 w-6" /> */}
          <Image
            src="/logos/web-app-manifest-512x512.png"
            alt="TF Logo"
            width={32}
            height={32}
          />
          <span className="font-semibold">Trust Forge</span>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-4 py-4">
        {navigation.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/reports"
              ? pathname.startsWith("/reports") ||
                pathname.startsWith("/report")
              : pathname === item.href;

          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              )}
            >
              <Icon className="h-4 w-4" />
              {item.name}
            </Link>
          );
        })}
      </nav>

      <div className="border-t p-4">
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <div className="flex-1 text-sm">
              <p className="text-foreground">{authData.user?.email}</p>
            </div>
          </div>
          <Button
            variant="outline"
            className="w-full justify-start gap-2"
            onClick={() => auth.logout()}
          >
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>
      </div>
    </div>
  );
}
