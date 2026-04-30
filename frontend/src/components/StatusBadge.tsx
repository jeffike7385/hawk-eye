const colors: Record<string, string> = {
  queued: "bg-gray-500",
  enumerating: "bg-amber-500 text-gray-900",
  scanning: "bg-amber-500 text-gray-900",
  completed: "bg-green-500 text-gray-900",
  failed: "bg-red-500",
  cancelled: "bg-gray-600",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colors[status] || "bg-gray-600"}`}>
      {status}
    </span>
  );
}
