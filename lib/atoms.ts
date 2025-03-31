import { atom } from 'recoil';

export interface User {
  id: string;
  email: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
}

export interface ScanReport {
  id: string;
  status: 'pending' | 'completed' | 'failed';
  tfScore: number;
  vulnerabilities: {
    high: number;
    medium: number;
    low: number;
  };
  findings: Array<{
    type: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
  }>;
}

export interface ScanState {
  currentScanId: string | null;
  reports: ScanReport[];
}

export const authState = atom<AuthState>({
  key: 'authState',
  default: {
    user: null,
    token: null,
  },
});

export const scanState = atom<ScanState>({
  key: 'scanState',
  default: {
    currentScanId: null,
    reports: [],
  },
});