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

export type AssistantContextPriority = "critical" | "high" | "medium" | "low";

export interface AssistantFocusContext {
  id: string;
  kind: string;
  sourcePage: string;
  title: string;
  subtitle?: string;
  severity?: string;
  timestamp?: string;
  source?: string;
  payload?: unknown;
  metadata?: Record<string, unknown>;
  priority?: AssistantContextPriority;
}

interface AuthState {
  user: User | null;
  activeProject: ActiveProject | null;
  projectSelectPending: boolean;
  timeRange: TimeRange | null;
  hydrated: boolean;
  activeLogType: "web" | "windows";
  displayMode: "default" | "compact";
  assistantFocus: AssistantFocusContext | null;

  setUser: (user: User | null) => void;
  setActiveProject: (project: ActiveProject | null) => void;
  setProjectSelectPending: (pending: boolean) => void;
  setTimeRange: (range: TimeRange | null) => void;
  setHydrated: (hydrated: boolean) => void;
  setActiveLogType: (logType: "web" | "windows") => void;
  setDisplayMode: (mode: "default" | "compact") => void;
  setAssistantFocus: (focus: AssistantFocusContext | null) => void;
  clearAssistantFocus: () => void;
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
      assistantFocus: null,

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
      setAssistantFocus: (focus) => set({ assistantFocus: focus }),
      clearAssistantFocus: () => set({ assistantFocus: null }),

      logout: () =>
        set({
          user: null,
          activeProject: null,
          projectSelectPending: false,
          timeRange: null,
          activeLogType: "web",
          displayMode: "compact",
          assistantFocus: null,
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
