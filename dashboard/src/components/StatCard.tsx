import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: string;
  variant?: 'blue' | 'red' | 'amber' | 'emerald';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  variant = 'blue'
}) => {
  const variantStyles = {
    blue: 'border-blue-500/20 text-blue-400 bg-blue-500/5',
    red: 'border-red-500/20 text-red-400 bg-red-500/5',
    amber: 'border-amber-500/20 text-amber-400 bg-amber-500/5',
    emerald: 'border-emerald-500/20 text-emerald-400 bg-emerald-500/5',
  };

  return (
    <div className={`p-5 rounded-2xl border glass-panel relative overflow-hidden transition-all duration-300 hover:border-gray-700 hover:scale-[1.01]`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">{title}</p>
          <p className="text-3xl font-extrabold text-white mt-1 tracking-tight font-mono">{value}</p>
          {subtitle && <p className="text-xs text-gray-400 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-xl border ${variantStyles[variant]}`}>
          {icon}
        </div>
      </div>
    </div>
  );
};
