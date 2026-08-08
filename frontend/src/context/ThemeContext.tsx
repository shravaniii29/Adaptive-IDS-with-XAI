import { createContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";
export const ThemeContext = createContext<{ theme: Theme; toggleTheme: () => void } | undefined>(undefined);
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("theme") as Theme) || "dark");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem("theme", theme);
  }, [theme]);
  const value = useMemo(() => ({ theme, toggleTheme: () => setTheme((current) => current === "dark" ? "light" : "dark") }), [theme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
