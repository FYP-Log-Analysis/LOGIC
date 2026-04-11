import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";
import type { ProjectType } from "@/lib/client";

export interface User {
  username: string;
  role: "admin" | "analyst" | "user";
  userId: number;
  email: string;
}

export interface ActiveProject {
  id: string;
  name: string;
  project_type?: ProjectType;
}

export interface TimeRange {
  from: string;
  to: string;
}

interface AuthState {
  user: User | null;
  activeProject: ActiveProject | null;
  projectSelectPending: boolean;
  timeRange: TimeRange | null;
  hydrated: boolean;
  activeLogType: "web" | "windows";
  displayMode: "default" | "compact";

  setUser: (user: User | null) => void;
  setActiveProject: (project: ActiveProject | null) => void;
  setProjectSelectPending: (pending: boolean) => void;
  setTimeRange: (range: TimeRange | null) => void;
  setHydrated: (hydrated: boolean) => void;
  setActiveLogType: (logType: "web" | "windows") => void;
  setDisplayMode: (mode: "default" | "compact") => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      activeProject: null,
      projectSelectPending: false,
      timeRange: null,
      hydrated: false,
      activeLogType: "web",
      displayMode: "compact",

      setUser: (user) => set({ user }),
      setActiveProject: (project) => set((state) => ({
        activeProject: project,
        activeLogType: project?.project_type ?? state.activeLogType,
      })),
      setProjectSelectPending: (pending) => set({ projectSelectPending: pending }),
      setTimeRange: (range) => set({ timeRange: range }),
      setHydrated: (hydrated) => set({ hydrated }),
      setActiveLogType: (logType) => set({ activeLogType: logType }),
      setDisplayMode: (mode) => set({ displayMode: mode }),

      logout: () =>
        set({
          user: null,
          activeProject: null,
          projectSelectPending: false,
          timeRange: null,
          activeLogType: "web",
          displayMode: "compact",
        }),
    }),
    {
      name: "logic-dashboard-store",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        activeProject: state.activeProject,
        timeRange: state.timeRange,
        activeLogType: state.activeLogType,
        displayMode: state.displayMode,
      }),
      onRehydrateStorage: () => (state) => {
        state?.setHydrated(true);
      },
    },
  ),
);
