import type { Metadata } from "next";
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
    title: `${decoded} · Web 预览 — Neruton`,
    description: `通过 Neruton 路径代理免域名直接预览内网隧道 ${decoded} 的 Web 内容。`,
  };
}

export default async function PreviewPage({ params }: PreviewPageProps) {
  const { prefix } = await params;
  const decoded = decodeURIComponent(prefix);
  return <PreviewViewerClient prefix={decoded} />;
}
