"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

export type ViewMode = "beginner" | "professional" | "executive" | "developer";

interface ViewModeContextType {
  mode: ViewMode;
  setMode: (mode: ViewMode) => void;
  isBeginner: boolean;
  isProfessional: boolean;
  isExecutive: boolean;
  isDeveloper: boolean;
}

const ViewModeContext = createContext<ViewModeContextType>({
  mode: "professional",
  setMode: () => {},
  isBeginner: false,
  isProfessional: true,
  isExecutive: false,
  isDeveloper: false,
});

export function ViewModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ViewMode>("professional");

  useEffect(() => {
    const saved = localStorage.getItem("vulnforge_view_mode") as ViewMode;
    if (saved && ["beginner", "professional", "executive", "developer"].includes(saved)) {
      setModeState(saved);
    }
  }, []);

  const setMode = (newMode: ViewMode) => {
    setModeState(newMode);
    localStorage.setItem("vulnforge_view_mode", newMode);
  };

  return (
    <ViewModeContext.Provider
      value={{
        mode,
        setMode,
        isBeginner: mode === "beginner",
        isProfessional: mode === "professional",
        isExecutive: mode === "executive",
        isDeveloper: mode === "developer",
      }}
    >
      {children}
    </ViewModeContext.Provider>
  );
}

export function useViewMode() {
  return useContext(ViewModeContext);
}
