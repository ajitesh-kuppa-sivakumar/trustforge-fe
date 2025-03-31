"use client";

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useRecoilState } from 'recoil';
import Cookies from 'js-cookie';
import { authState } from '@/lib/atoms';

const publicPaths = ['/login', '/register', '/'];

export default function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuth] = useRecoilState(authState);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const token = Cookies.get('token');
    const isPublicPath = publicPaths.includes(pathname);

    if (!token && !isPublicPath) {
      router.push('/login');
    }

    if (token && isPublicPath && pathname !== '/') {
      router.push('/dashboard');
    }

    if (token && !auth.token) {
      // Restore auth state from cookie
      setAuth({ token, user: JSON.parse(Cookies.get('user') || '{}') });
    }
  }, [pathname, auth.token, router, setAuth]);

  return <>{children}</>;
}