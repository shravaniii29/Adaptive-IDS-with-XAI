import Card from "../common/Card";

interface StatCardProps {
  title: string;

  value: string | number;

  color: string;
}

export default function StatCard({
  title,
  value,
  color,
}: StatCardProps) {
  return (
    <Card className="flex flex-col gap-4">

      <p className="text-sm text-slate-400">
        {title}
      </p>

      <h1
        className="text-4xl font-bold"
        style={{ color }}
      >
        {value}
      </h1>

    </Card>
  );
}