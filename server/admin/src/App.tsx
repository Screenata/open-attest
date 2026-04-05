import { useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from '@/components/ui/sonner';
import { AuthContext, getStoredAuth, setStoredAuth, clearStoredAuth } from '@/lib/auth';
import type { AuthState } from '@/lib/auth';
import Layout from '@/components/Layout';
import Login from '@/pages/Login';
import Dashboard from '@/pages/Dashboard';
import Devices from '@/pages/Devices';
import DeviceDetail from '@/pages/DeviceDetail';
import ApiKeys from '@/pages/ApiKeys';

export default function App() {
  const [auth, setAuthState] = useState<AuthState>(getStoredAuth);

  const setAuth = useCallback((a: AuthState) => {
    setStoredAuth(a);
    setAuthState(a);
  }, []);

  const logout = useCallback(() => {
    clearStoredAuth();
    setAuthState(null);
  }, []);

  const isAdmin = auth?.type === 'admin_secret';

  return (
    <AuthContext.Provider value={{ auth, setAuth, logout, isAdmin }}>
      <BrowserRouter>
        <Routes>
          <Route path="/admin" element={auth ? <Navigate to="/admin/dashboard" replace /> : <Login />} />
          <Route path="/admin/" element={auth ? <Navigate to="/admin/dashboard" replace /> : <Login />} />
          <Route element={auth ? <Layout /> : <Navigate to="/admin/" replace />}>
            <Route path="/admin/dashboard" element={<Dashboard />} />
            <Route path="/admin/devices" element={<Devices />} />
            <Route path="/admin/devices/:deviceId" element={<DeviceDetail />} />
            <Route path="/admin/credentials" element={<ApiKeys />} />
            <Route path="/admin/*" element={<Navigate to="/admin/dashboard" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/admin/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster />
    </AuthContext.Provider>
  );
}
