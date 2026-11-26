import React from "react";

interface LogoProps {
  className?: string;
}

export function Logo({ className = "h-8 w-8" }: LogoProps) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id="neruton-logo-grad"
          x1="8"
          y1="8"
          x2="56"
          y2="56"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#06b6d4" />
          <stop offset="100%" stopColor="#10b981" />
        </linearGradient>
      </defs>
      <rect
        width="64"
        height="64"
        rx="16"
        className="fill-zinc-900 dark:fill-zinc-950"
      />
      <rect
        x="2"
        y="2"
        width="60"
        height="60"
        rx="14"
        stroke="url(#neruton-logo-grad)"
        strokeOpacity="0.55"
        strokeWidth="2.5"
      />
      <path
        d="M18 44V20L46 44V20"
        stroke="url(#neruton-logo-grad)"
        strokeWidth="5.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="18" cy="20" r="4" fill="#22d3ee" />
      <circle cx="46" cy="44" r="4" fill="#34d399" />
    </svg>
  );
}
