import { Moon, Sun } from "lucide-react";
import { useTheme } from "../../hooks/useTheme";

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return <button aria-label="Toggle colour theme" onClick={toggleTheme} className="rounded-lg p-2 text-slate-400 transition hover:bg-white/10 hover:text-white">{theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}</button>;
}
