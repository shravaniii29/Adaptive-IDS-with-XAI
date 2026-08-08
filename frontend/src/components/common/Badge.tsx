import clsx from "clsx";

interface BadgeProps {
  text: string;

  variant?: "success" | "danger" | "warning" | "info";
}

export default function Badge({
  text,
  variant = "info",
}: BadgeProps) {
  const styles = {
    success:
      "bg-green-500/10 text-green-400",

    danger:
      "bg-red-500/10 text-red-400",

    warning:
      "bg-yellow-500/10 text-yellow-400",

    info:
      "bg-sky-500/10 text-sky-400",
  };

  return (
    <span
      className={clsx(
        "rounded-full",
        "px-3",
        "py-1",
        "text-xs",
        "font-medium",
        styles[variant]
      )}
    >
      {text}
    </span>
  );
}