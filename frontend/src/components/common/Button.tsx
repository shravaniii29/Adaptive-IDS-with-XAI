import clsx from "clsx";
import type { ButtonHTMLAttributes, ReactNode } from "react";
type Props = ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode; variant?: "primary" | "secondary" | "danger" };
export default function Button({ children, className, variant = "primary", ...props }: Props) { return <button className={clsx("rounded-lg px-4 py-2 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-indigo-400 disabled:cursor-not-allowed disabled:opacity-50", { "bg-indigo-500 text-white hover:bg-indigo-400": variant === "primary", "bg-white/10 text-slate-100 hover:bg-white/15": variant === "secondary", "bg-rose-500/15 text-rose-200 hover:bg-rose-500/25": variant === "danger" }, className)} {...props}>{children}</button>; }
