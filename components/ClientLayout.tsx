"use client";

import { RecoilRoot } from "recoil";
import { Toaster } from "@/components/ui/sonner";
import AuthProvider from "@/components/AuthProvider";

export default function ClientLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <RecoilRoot>
      <AuthProvider>{children}</AuthProvider>
      <Toaster />
    </RecoilRoot>
  );
}
