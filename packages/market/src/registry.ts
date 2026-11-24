import type { Kind, Product } from "./review.ts";

export interface IndexVersion {
  item: string;
  name: string;
  version: string;
  summary: string;
  publisher: string;
  publisherName: string;
  homepage: string;
  engine: string;
  kind: Kind;
  product: Product;
  paid: boolean;
  sha256: string;
  signature: string;
  size: number;
  advisories?: { id: string; severity: "low" | "medium" | "high" | "critical"; title: string; affected: string; fixed: string | null; url: string; published: number }[];
}

export function registryIndex(name: string, base: string, product: Product, versions: readonly IndexVersion[]) {
  return {
    name,
    plugins: versions
      .filter((v) => v.product === product && (v.kind === "plugin" || v.kind === "theme"))
      .map((v) => ({
        id: v.item,
        name: v.name,
        version: v.version,
        description: v.summary,
        author: v.publisherName,
        homepage: v.homepage,
        engine: v.engine,
        url: v.paid ? `${base}/api/v1/licences/package/${encodeURIComponent(v.item)}/${encodeURIComponent(v.version)}` : `${base}/api/v1/packages/${encodeURIComponent(v.item)}/${encodeURIComponent(v.version)}`,
        sha256: v.paid ? "" : v.sha256,
        signature: v.paid ? "" : v.signature,
        size: v.size,
        kind: v.kind === "theme" ? "theme" : "plugin",
        publisher: v.publisher,
        paid: v.paid,
        advisories: v.advisories ?? [],
      })),
  };
}
