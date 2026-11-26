import type { Metadata } from "next";
import { AuthGuard } from "@/components/AuthGuard";
import { PreviewViewerClient } from "@/components/PreviewViewerClient";

interface PreviewPageProps {
  params: Promise<{ prefix: string }>;
}

export async function generateMetadata({
  params,
}: PreviewPageProps): Promise<Metadata> {
  const { prefix } = await params;
  const decoded = decodeURIComponent(prefix);
  return {
    title: `${decoded} · 预览 — Neruton`,
    description: `通过 Neruton 路径代理预览内网隧道 ${decoded}。`,
  };
}

export default async function PreviewPage({ params }: PreviewPageProps) {
  const { prefix } = await params;
  const decoded = decodeURIComponent(prefix);
  return (
    <AuthGuard>
      <PreviewViewerClient prefix={decoded} />
    </AuthGuard>
  );
}
