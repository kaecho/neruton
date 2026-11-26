import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Neruton — 内网穿透网关控制台",
  description:
    "轻量化自托管内网穿透网关管理面板：支持泛域名路由、自动 UUID / 自定义子域名前缀、Web 内嵌预览与实时 HTTP/WS 流量监控。",
  icons: {
    icon: "/favicon.svg",
  },
};

const themeInitScript = `
(function() {
  try {
    var stored = localStorage.getItem('neruton_theme');
    if (stored === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  } catch (e) {
    document.documentElement.classList.add('dark');
  }
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN" className="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-screen bg-zinc-50 text-zinc-900 antialiased selection:bg-cyan-500/25 selection:text-cyan-900 dark:bg-[#09090b] dark:text-zinc-100 dark:selection:bg-cyan-500/30 dark:selection:text-cyan-100">
        {children}
      </body>
    </html>
  );
}
