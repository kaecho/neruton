import type { Metadata } from "next";
import { AuthGuard } from "@/components/AuthGuard";
import { PreviewViewerClient } from "@/components/PreviewViewerClient";

interface PreviewPageProps {
  params: Promise<{ prefix: string }>;
}

export const metadata: Metadata = {
  title: "Neruton",
  description: "Neruton",
};

export default async function PreviewPage({ params }: PreviewPageProps) {
  const { prefix } = await params;
  const decoded = decodeURIComponent(prefix);
  return (
    <AuthGuard>
      <PreviewViewerClient prefix={decoded} />
    </AuthGuard>
  );
}
