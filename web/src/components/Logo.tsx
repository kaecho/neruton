import React from "react";

interface LogoProps {
  className?: string;
}

export function Logo({ className = "h-5 w-5" }: LogoProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <rect
        width="24"
        height="24"
        rx="5"
        className="fill-foreground"
      />
      <path
        d="M6.75 17.5V6.5H9.4L14.6 13.9V6.5H17.25V17.5H14.6L9.4 10.1V17.5H6.75Z"
        className="fill-background"
      />
    </svg>
  );
}
