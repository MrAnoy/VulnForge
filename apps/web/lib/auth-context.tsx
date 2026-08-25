'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from './api';

interface User {
  id: string;
  email: string;
  full_name: string;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
}

interface Project {
  id: string;
  organization_id: string;
  name: string;
  client_name?: string;
  description?: string;
  environment: string;
  risk_score: number;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  organizations: Organization[];
  currentOrg: Organization | null;
  projects: Project[];
  currentProject: Project | null;
  loading: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
  setCurrentOrg: (org: Organization) => void;
  setCurrentProject: (proj: Project) => void;
  refreshUserData: () => Promise<void>;
  switchDemoUser: (role: 'admin' | 'analyst' | 'viewer') => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedToken = localStorage.getItem('vulnforge_token');
    const savedUser = localStorage.getItem('vulnforge_user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      try {
        setUser(JSON.parse(savedUser));
      } catch {
        // ignore
      }
    }
    setLoading(false);
  }, []);

  const refreshUserData = async () => {
    try {
      const orgs = await api.getOrganizations();
      setOrganizations(orgs);
      if (orgs.length > 0) {
        const activeOrg = currentOrg && orgs.some(o => o.id === currentOrg.id) ? currentOrg : orgs[0];
        setCurrentOrg(activeOrg);
        const projs = await api.getProjects(activeOrg.id);
        setProjects(projs);
        if (projs.length > 0) {
          const activeProj = currentProject && projs.some(p => p.id === currentProject.id) ? currentProject : projs[0];
          setCurrentProject(activeProj);
        } else {
          setCurrentProject(null);
        }
      }
    } catch (err) {
      console.error('Failed to load user organizations & projects', err);
    }
  };

  useEffect(() => {
    if (token) {
      refreshUserData();
    }
  }, [token]);

  useEffect(() => {
    if (currentOrg) {
      api.getProjects(currentOrg.id).then(projs => {
        setProjects(projs);
        if (projs.length > 0 && (!currentProject || !projs.some(p => p.id === currentProject.id))) {
          setCurrentProject(projs[0]);
        }
      }).catch(console.error);
    }
  }, [currentOrg]);

  const login = (newToken: string, newUser: User) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('vulnforge_token', newToken);
    localStorage.setItem('vulnforge_user', JSON.stringify(newUser));
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setOrganizations([]);
    setCurrentOrg(null);
    setProjects([]);
    setCurrentProject(null);
    localStorage.removeItem('vulnforge_token');
    localStorage.removeItem('vulnforge_user');
  };

  const switchDemoUser = async (role: 'admin' | 'analyst' | 'viewer') => {
    const emails = {
      admin: 'admin@vulnforge.sec',
      analyst: 'analyst@vulnforge.sec',
      viewer: 'viewer@vulnforge.sec',
    };
    try {
      const res = await api.login({ email: emails[role], password: 'VulnForgeDemo2026!' });
      login(res.access_token, res.user);
      await refreshUserData();
    } catch (err) {
      console.error('Failed switching demo user:', err);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        organizations,
        currentOrg,
        projects,
        currentProject,
        loading,
        login,
        logout,
        setCurrentOrg,
        setCurrentProject,
        refreshUserData,
        switchDemoUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
