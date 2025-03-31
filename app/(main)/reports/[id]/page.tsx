"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Info,
  Loader2,
  Bug,
  ShieldCheck,
  Scan,
  Activity,
  Clock,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { scan } from "@/lib/api";

type ScanStatus = "pending" | "completed" | "failed";

interface StatusResponse {
  status: ScanStatus;
}

interface Finding {
  type: string;
  severity: "high" | "medium" | "low";
  description: string;
  location?: string;
  files?: string[];
}

interface Recommendation {
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
}

interface ScanReport {
  tfScore: number;
  vulnerabilities: {
    high: number;
    medium: number;
    low: number;
  };
  findings: Finding[];
  recommendations: Recommendation[];
  metadata: {
    appName: string;
    packageName: string;
    version: string;
    size: string;
    sha256: string;
  };
  virustotal?:
    | {
        [key: string]: {
          method: string;
          result: string | null;
          category: string;
          engine_name: string;
          engine_update: string;
          engine_version: string;
        };
      }
    | { error: string };
  metadefender?: {
    total_avs: number;
    total_detected_avs: number;
    scan_all_result_a: string;
    scan_details: {
      [key: string]: {
        def_time: string;
        location: string;
        scan_time: number;
        threat_found: string;
        scan_result_i: number;
      };
    };
  };
  hybridanalysis?: {
    verdict: string;
    threat_score: number;
    threat_level: number;
    av_detect: number;
    signatures: {
      name: string;
      threat_level: number;
      description: string;
    }[];
    mitre_attcks: {
      technique: string;
      tactic: string;
      malicious_identifiers_count: number;
    }[];
    extracted_files?: {
      name: string;
      threat_level: number;
      description: string;
      threat_level_readable: string;
    }[];
  };
}

const SEVERITY_COLORS = {
  high: "text-red-500",
  medium: "text-yellow-500",
  low: "text-green-500",
};

const PRIORITY_ICONS = {
  critical: <AlertTriangle className="h-5 w-5 text-red-500 mt-1" />,
  high: <AlertTriangle className="h-5 w-5 text-orange-500 mt-1" />,
  medium: <Info className="h-5 w-5 text-yellow-500 mt-1" />,
  low: <Info className="h-5 w-5 text-blue-500 mt-1" />,
};

const ANTIVIRUS_STATUS_COLORS = {
  undetected: "bg-green-500/10 text-green-500",
  detected: "bg-red-500/10 text-red-500",
  failure: "bg-yellow-500/10 text-yellow-500",
  "type-unsupported": "bg-gray-500/10 text-gray-500",
};

const THREAT_LEVEL_COLORS = {
  0: "bg-green-500/10 text-green-500",
  1: "bg-yellow-500/10 text-yellow-500",
  2: "bg-orange-500/10 text-orange-500",
  3: "bg-red-500/10 text-red-500",
};

const THREAT_LEVEL_TEXT = {
  0: "No threat",
  1: "Suspicious",
  2: "Malicious",
  3: "Highly malicious",
};

const getPriorityFromSeverity = (
  severity: string
): "critical" | "high" | "medium" | "low" => {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "low";
  }
};

export default function ReportPage() {
  const { id } = useParams();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>(
    "pending" as ScanStatus
  );

  const transformData = (data: any): ScanReport => {
    if (!data) {
      throw new Error("No data received from API");
    }

    const findings: Finding[] = [];
    const recommendations: Recommendation[] = [];

    if (data.mobsf?.appsec?.high) {
      data.mobsf.appsec.high.forEach((issue: any) => {
        findings.push({
          type: issue.title || "Unknown Issue",
          severity: "high",
          description: issue.description || "No description available",
          location: issue.section,
          files: issue.files ? [].concat(issue.files) : undefined,
        });

        if (issue.remediation) {
          recommendations.push({
            title: issue.title || "Security Recommendation",
            description: issue.remediation,
            priority: "high",
          });
        }
      });
    }

    if (data.mobsf?.appsec?.warning) {
      data.mobsf.appsec.warning.forEach((issue: any) => {
        findings.push({
          type: issue.title || "Unknown Issue",
          severity: "medium",
          description: issue.description || "No description available",
          location: issue.section,
          files: issue.files ? [].concat(issue.files) : undefined,
        });

        if (issue.remediation) {
          recommendations.push({
            title: issue.title || "Security Recommendation",
            description: issue.remediation,
            priority: "medium",
          });
        }
      });
    }

    if (data.mobsf?.appsec?.info) {
      data.mobsf.appsec.info.forEach((issue: any) => {
        findings.push({
          type: issue.title || "Unknown Issue",
          severity: "low",
          description: issue.description || "No description available",
          location: issue.section,
          files: issue.files ? [].concat(issue.files) : undefined,
        });
      });
    }

    if (data.certificate_analysis?.certificate_findings) {
      data.certificate_analysis.certificate_findings.forEach((issue: any) => {
        findings.push({
          type: issue[2] || "Certificate Issue",
          severity:
            issue[0] === "high"
              ? "high"
              : issue[0] === "warning"
              ? "medium"
              : "low",
          description: issue[1] || "No description available",
          location: "Certificate",
        });

        if (issue[0] === "high" || issue[0] === "warning") {
          recommendations.push({
            title: "Certificate Security",
            description:
              "Review and update the certificate configuration to meet security best practices.",
            priority: getPriorityFromSeverity(issue[0]),
          });
        }
      });
    }

    if (data.manifest_analysis?.manifest_findings) {
      data.manifest_analysis.manifest_findings.forEach((issue: any) => {
        findings.push({
          type: issue.title || "Manifest Issue",
          severity: issue.severity === "high" ? "high" : "medium",
          description: issue.description || "No description available",
          location: `Manifest: ${
            issue.component ? issue.component.join(" > ") : "Unknown"
          }`,
        });

        if (issue.severity === "high" || issue.severity === "warning") {
          recommendations.push({
            title: "Manifest Security",
            description: issue.description.includes("exported")
              ? "Review exported components and implement proper protection mechanisms."
              : "Review manifest configuration to address security issues.",
            priority: getPriorityFromSeverity(issue.severity),
          });
        }
      });
    }

    if (recommendations.length === 0) {
      recommendations.push(
        {
          title: "Update Cryptographic Implementation",
          description:
            "Replace MD5 with SHA-256 or stronger hashing algorithm. Change CBC mode to GCM for encryption.",
          priority: "high",
        },
        {
          title: "Minimum SDK Version",
          description:
            "Raise minimum SDK to API 29 (Android 10) for better security.",
          priority: "medium",
        },
        {
          title: "Input Validation",
          description:
            "Implement parameterized queries for all SQL operations. Sanitize all user inputs.",
          priority: "high",
        }
      );
    }

    const highCount =
      (data.mobsf?.appsec?.high?.length || 0) +
      (data.certificate_analysis?.certificate_findings?.filter(
        (x: any) => x[0] === "high"
      ).length || 0) +
      (data.manifest_analysis?.manifest_findings?.filter(
        (x: any) => x.severity === "high"
      ).length || 0);

    const mediumCount =
      (data.mobsf?.appsec?.warning?.length || 0) +
      (data.certificate_analysis?.certificate_findings?.filter(
        (x: any) => x[0] === "warning"
      ).length || 0) +
      (data.manifest_analysis?.manifest_findings?.filter(
        (x: any) => x.severity === "warning"
      ).length || 0);

    const lowCount =
      (data.mobsf?.appsec?.info?.length || 0) +
      (data.certificate_analysis?.certificate_findings?.filter(
        (x: any) => x[0] === "info"
      ).length || 0);

    return {
      tfScore: data.tfScore || 0,
      vulnerabilities: {
        high: highCount,
        medium: mediumCount,
        low: lowCount,
      },
      findings,
      recommendations,
      metadata: {
        appName: data.mobsf?.app_name || "Unknown App",
        packageName: data.mobsf?.package_name || "Unknown Package",
        version: data.mobsf?.version || "Unknown Version",
        size: data.mobsf?.size || "0 MB",
        sha256: data.mobsf?.sha256 || "Unknown Hash",
      },
      virustotal: data.virustotal,
      metadefender: data.metadefender,
      hybridanalysis: data.hybridAnalysis
        ? {
            verdict: data.hybridAnalysis.verdict,
            threat_score: data.hybridAnalysis.threat_score,
            threat_level: data.hybridAnalysis.threat_level,
            av_detect: data.hybridAnalysis.av_detect,
            signatures: data.hybridAnalysis.signatures?.map((sig: any) => ({
              name: sig.name,
              threat_level: sig.threat_level,
              description: sig.description,
            })),
            mitre_attcks: data.hybridAnalysis.mitre_attcks?.map(
              (attck: any) => ({
                technique: attck.technique,
                tactic: attck.tactic,
                malicious_identifiers_count: attck.malicious_identifiers_count,
              })
            ),
            extracted_files: data.hybridAnalysis.extracted_files?.map(
              (file: any) => ({
                name: file.name,
                threat_level: file.threat_level,
                description: file.description,
                threat_level_readable: file.threat_level_readable,
              })
            ),
          }
        : undefined,
    };
  };

  const checkScanStatus = useCallback(async () => {
    try {
      setIsLoading(true);
      const scanId = Array.isArray(id) ? id[0] : id;
      if (!scanId) {
        throw new Error("No scan ID provided");
      }

      const statusResponse: StatusResponse = await scan.getStatus(scanId);
      setScanStatus(statusResponse.status);

      if (statusResponse.status === "pending") {
        const timer = setTimeout(() => {
          checkScanStatus();
        }, 30000);
        return () => clearTimeout(timer);
      }

      if (statusResponse.status === "completed") {
        const rawData = await scan.getReport(scanId);
        if (!rawData) {
          throw new Error("Empty response from server");
        }

        const fullData =
          typeof rawData === "string" ? JSON.parse(rawData) : rawData;
        const transformedData = transformData(fullData);
        setReport(transformedData);
        setError(null);
      }

      if (statusResponse.status === "failed") {
        setError("Scan failed to complete. Please try again.");
      }
    } catch (err) {
      console.error("Failed to check scan status:", err);
      setError(err instanceof Error ? err.message : "Unknown error occurred");
      toast.error("Failed to load scan status");
    } finally {
      setIsLoading(false);
    }
  }, [id]);

  const retryScan = async () => {
    try {
      setIsLoading(true);
      const scanId = Array.isArray(id) ? id[0] : id;
      if (!scanId) {
        throw new Error("No scan ID provided");
      }

      const response = await fetch(`/api/scan/retry/${scanId}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to retry scan");
      }

      const data = await response.json();
      toast.success(data.message);
      setScanStatus("pending");
      checkScanStatus();
    } catch (err) {
      console.error("Failed to retry scan:", err);
      setError(err instanceof Error ? err.message : "Failed to retry scan");
      toast.error("Failed to retry scan");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkScanStatus();
  }, [checkScanStatus]);

  const renderVirusTotalCard = () => {
    if (!report?.virustotal || "error" in report.virustotal) {
      return (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5" />
              VirusTotal
            </CardTitle>
            <CardDescription>
              {report?.virustotal && "error" in report.virustotal
                ? String(report.virustotal.error)
                : "No VirusTotal data available"}
            </CardDescription>
          </CardHeader>
        </Card>
      );
    }

    const engines = Object.entries(report.virustotal);
    const detectedEngines = engines.filter(
      ([_, result]) =>
        result.category !== "undetected" &&
        result.category !== "type-unsupported"
    );

    return (
      <Card>
        <CardHeader>
          <CardDescription>
            Scanned by {engines.length} antivirus engines
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-green-500/10 rounded-lg">
                <div className="text-green-500 font-bold text-2xl">
                  {engines.length - detectedEngines.length}
                </div>
                <div className="text-sm text-muted-foreground">Clean</div>
              </div>
              <div className="text-center p-4 bg-red-500/10 rounded-lg">
                <div className="text-red-500 font-bold text-2xl">
                  {detectedEngines.length}
                </div>
                <div className="text-sm text-muted-foreground">Detections</div>
              </div>
              <div className="text-center p-4 bg-gray-500/10 rounded-lg">
                <div className="text-gray-500 font-bold text-2xl">
                  {
                    engines.filter((e) => e[1].category === "type-unsupported")
                      .length
                  }
                </div>
                <div className="text-sm text-muted-foreground">Unsupported</div>
              </div>
            </div>

            {detectedEngines.length > 0 && (
              <div className="space-y-2">
                <h3 className="font-semibold">Detections Found</h3>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Engine</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Version</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detectedEngines.map(([engine, result]) => (
                      <TableRow key={engine}>
                        <TableCell className="font-medium">{engine}</TableCell>
                        <TableCell>{result.result || "Unknown"}</TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              ANTIVIRUS_STATUS_COLORS[
                                result.category as keyof typeof ANTIVIRUS_STATUS_COLORS
                              ] || "bg-gray-500/10 text-gray-500"
                            }
                          >
                            {result.category}
                          </Badge>
                        </TableCell>
                        <TableCell>{result.engine_version}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <Accordion type="single" collapsible>
              <AccordionItem value="all-engines">
                <AccordionTrigger className="text-sm">
                  View all scan results ({engines.length} engines)
                </AccordionTrigger>
                <AccordionContent>
                  <div className="max-h-96 overflow-y-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Engine</TableHead>
                          <TableHead>Result</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Version</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {engines.map(([engine, result]) => (
                          <TableRow key={engine}>
                            <TableCell className="font-medium">
                              {engine}
                            </TableCell>
                            <TableCell>{result.result || "Clean"}</TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={
                                  ANTIVIRUS_STATUS_COLORS[
                                    result.category as keyof typeof ANTIVIRUS_STATUS_COLORS
                                  ] || "bg-gray-500/10 text-gray-500"
                                }
                              >
                                {result.category}
                              </Badge>
                            </TableCell>
                            <TableCell>{result.engine_version}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </CardContent>
      </Card>
    );
  };

  const renderMetaDefenderCard = () => {
    if (!report?.metadefender) {
      return (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              MetaDefender Cloud
            </CardTitle>
            <CardDescription>No MetaDefender data available</CardDescription>
          </CardHeader>
        </Card>
      );
    }

    const { total_avs, total_detected_avs, scan_all_result_a, scan_details } =
      report.metadefender;
    const scanResults = Object.entries(scan_details);

    return (
      <Card>
        <CardHeader>
          <CardDescription>
            Scanned by {total_avs} antivirus engines
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-green-500/10 rounded-lg">
                <div className="text-green-500 font-bold text-2xl">
                  {total_avs - total_detected_avs}
                </div>
                <div className="text-sm text-muted-foreground">Clean</div>
              </div>
              <div className="text-center p-4 bg-red-500/10 rounded-lg">
                <div className="text-red-500 font-bold text-2xl">
                  {total_detected_avs}
                </div>
                <div className="text-sm text-muted-foreground">Detections</div>
              </div>
              <div className="text-center p-4 bg-blue-500/10 rounded-lg">
                <div className="text-blue-500 font-bold text-2xl">
                  {scan_all_result_a}
                </div>
                <div className="text-sm text-muted-foreground">
                  Final Result
                </div>
              </div>
            </div>

            <Accordion type="single" collapsible>
              <AccordionItem value="scan-details">
                <AccordionTrigger className="text-sm">
                  View scan details ({scanResults.length} engines)
                </AccordionTrigger>
                <AccordionContent>
                  <div className="max-h-96 overflow-y-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Engine</TableHead>
                          <TableHead>Result</TableHead>
                          <TableHead>Scan Time</TableHead>
                          <TableHead>Last Updated</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scanResults.map(([engine, result]) => (
                          <TableRow key={engine}>
                            <TableCell className="font-medium">
                              {engine}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={
                                  result.threat_found
                                    ? "bg-red-500/10 text-red-500"
                                    : "bg-green-500/10 text-green-500"
                                }
                              >
                                {result.threat_found || "Clean"}
                              </Badge>
                            </TableCell>
                            <TableCell>{result.scan_time}ms</TableCell>
                            <TableCell>
                              {new Date(result.def_time).toLocaleDateString()}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </CardContent>
      </Card>
    );
  };

  const renderHybridAnalysisCard = () => {
    if (!report?.hybridanalysis) {
      return (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Hybrid Analysis
            </CardTitle>
            <CardDescription>No Hybrid Analysis data available</CardDescription>
          </CardHeader>
        </Card>
      );
    }

    const {
      verdict,
      threat_score,
      threat_level,
      av_detect,
      signatures,
      mitre_attcks,
      extracted_files,
    } = report.hybridanalysis;

    const maliciousSignatures =
      signatures?.filter((sig) => sig.threat_level >= 1) || [];
    const informativeSignatures =
      signatures?.filter((sig) => sig.threat_level === 0) || [];

    return (
      <Card>
        <CardHeader>
          <CardDescription>
            Behavioral analysis and threat intelligence
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-blue-500/10 rounded-lg">
                <div className="text-blue-500 font-bold text-2xl">
                  {verdict}
                </div>
                <div className="text-sm text-muted-foreground">Verdict</div>
              </div>
              <div className="text-center p-4 bg-purple-500/10 rounded-lg">
                <div className="text-purple-500 font-bold text-2xl">
                  {threat_score}/100
                </div>
                <div className="text-sm text-muted-foreground">
                  Threat Score
                </div>
              </div>
              <div className="text-center p-4 bg-orange-500/10 rounded-lg">
                <div className="text-orange-500 font-bold text-2xl">
                  {av_detect || 0}
                </div>
                <div className="text-sm text-muted-foreground">
                  AV Detections
                </div>
              </div>
              <div
                className="text-center p-4 rounded-lg"
                style={{
                  backgroundColor:
                    threat_level === 0
                      ? "rgba(16, 185, 129, 0.1)"
                      : threat_level === 1
                      ? "rgba(234, 179, 8, 0.1)"
                      : threat_level === 2
                      ? "rgba(249, 115, 22, 0.1)"
                      : "rgba(239, 68, 68, 0.1)",
                  color:
                    threat_level === 0
                      ? "rgb(16, 185, 129)"
                      : threat_level === 1
                      ? "rgb(234, 179, 8)"
                      : threat_level === 2
                      ? "rgb(249, 115, 22)"
                      : "rgb(239, 68, 68)",
                }}
              >
                <div className="font-bold text-2xl">
                  {THREAT_LEVEL_TEXT[
                    threat_level as keyof typeof THREAT_LEVEL_TEXT
                  ] || "Unknown"}
                </div>
                <div className="text-sm text-muted-foreground">
                  Threat Level
                </div>
              </div>
            </div>

            {mitre_attcks && mitre_attcks.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">MITRE ATT&CK Techniques</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {mitre_attcks.map((attck, index) => (
                    <div key={index} className="p-3 bg-secondary/30 rounded-lg">
                      <div className="font-medium">{attck.technique}</div>
                      <div className="text-sm text-muted-foreground">
                        {attck.tactic}
                      </div>
                      {attck.malicious_identifiers_count > 0 && (
                        <div className="text-xs mt-1">
                          <span className="text-red-500">
                            {attck.malicious_identifiers_count} malicious
                            indicators
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {maliciousSignatures.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">
                  Threat Indicators ({maliciousSignatures.length})
                </h3>
                <Accordion type="multiple" className="w-full">
                  {maliciousSignatures.map((signature, index) => (
                    <AccordionItem
                      key={index}
                      value={`signature-${index}`}
                      className="border-b"
                    >
                      <AccordionTrigger className="px-4 sm:px-6 py-4 hover:no-underline">
                        <div className="flex items-center space-x-3">
                          <Badge
                            variant="outline"
                            className={
                              THREAT_LEVEL_COLORS[
                                signature.threat_level as keyof typeof THREAT_LEVEL_COLORS
                              ] || "bg-gray-500/10 text-gray-500"
                            }
                          >
                            {THREAT_LEVEL_TEXT[
                              signature.threat_level as keyof typeof THREAT_LEVEL_TEXT
                            ] || "Unknown"}
                          </Badge>
                          <span className="font-medium text-left">
                            {signature.name}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 sm:px-6 pb-4">
                        <div className="space-y-2">
                          <p className="text-muted-foreground text-sm">
                            {signature.description}
                          </p>
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </div>
            )}

            {informativeSignatures.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">
                  Informational Findings ({informativeSignatures.length})
                </h3>
                <Accordion type="multiple" className="w-full">
                  {informativeSignatures.map((signature, index) => (
                    <AccordionItem
                      key={index}
                      value={`info-signature-${index}`}
                      className="border-b"
                    >
                      <AccordionTrigger className="px-4 sm:px-6 py-4 hover:no-underline">
                        <div className="flex items-center space-x-3">
                          <Badge
                            variant="outline"
                            className="bg-blue-500/10 text-blue-500"
                          >
                            Informational
                          </Badge>
                          <span className="font-medium text-left">
                            {signature.name}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 sm:px-6 pb-4">
                        <div className="space-y-2">
                          <p className="text-muted-foreground text-sm">
                            {signature.description}
                          </p>
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </div>
            )}

            {extracted_files && extracted_files.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">
                  Extracted Files ({extracted_files.length})
                </h3>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>File Name</TableHead>
                      <TableHead>Threat Level</TableHead>
                      <TableHead>Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {extracted_files.map((file, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-medium">
                          {file.name}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              THREAT_LEVEL_COLORS[
                                file.threat_level as keyof typeof THREAT_LEVEL_COLORS
                              ] || "bg-gray-500/10 text-gray-500"
                            }
                          >
                            {file.threat_level_readable}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {file.description}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    );
  };

  const renderMobSFTabs = () => {
    if (!report) return null;

    return (
      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="findings">
            Findings ({report.findings.length})
          </TabsTrigger>
          <TabsTrigger value="recommendations">
            Recommendations ({report.recommendations.length})
          </TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="mt-4">
          <Card>
            <CardContent className="p-0">
              {report.findings.length === 0 ? (
                <div className="p-6 text-center text-muted-foreground">
                  No security findings detected.
                </div>
              ) : (
                <Accordion type="multiple" className="w-full">
                  {report.findings.map((finding, index) => (
                    <AccordionItem
                      key={index}
                      value={`item-${index}`}
                      className="border-b"
                    >
                      <AccordionTrigger className="px-4 sm:px-6 py-4 hover:no-underline">
                        <div className="flex items-center space-x-3">
                          {finding.severity === "high" && (
                            <AlertTriangle className="h-5 w-5 text-red-500" />
                          )}
                          {finding.severity === "medium" && (
                            <Info className="h-5 w-5 text-yellow-500" />
                          )}
                          {finding.severity === "low" && (
                            <CheckCircle className="h-5 w-5 text-green-500" />
                          )}
                          <span
                            className={`font-medium text-left ${
                              SEVERITY_COLORS[finding.severity]
                            }`}
                          >
                            {finding.type}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 sm:px-6 pb-4">
                        <div className="space-y-4">
                          <p className="text-muted-foreground">
                            {finding.description}
                          </p>

                          {finding.location && (
                            <div className="text-sm">
                              <span className="font-medium">Location: </span>
                              <span className="text-muted-foreground">
                                {finding.location}
                              </span>
                            </div>
                          )}

                          {finding.files && finding.files.length > 0 && (
                            <div className="text-sm">
                              <span className="font-medium">
                                Affected Files:{" "}
                              </span>
                              <div className="mt-1 space-y-1">
                                {finding.files.map((file, i) => (
                                  <div
                                    key={i}
                                    className="font-mono text-xs bg-secondary/50 p-2 rounded break-all"
                                  >
                                    {file}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="recommendations" className="mt-4">
          <Card>
            <CardContent className="p-4 sm:p-6">
              <div className="space-y-4">
                {report.recommendations.length === 0 ? (
                  <div className="text-center text-muted-foreground">
                    No recommendations available.
                  </div>
                ) : (
                  report.recommendations.map((rec, index) => (
                    <div
                      key={index}
                      className="flex items-start space-x-4 p-4 bg-secondary/30 rounded-lg"
                    >
                      <div className="flex-shrink-0">
                        {PRIORITY_ICONS[rec.priority]}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold">{rec.title}</h3>
                        <p className="text-muted-foreground mt-1">
                          {rec.description}
                        </p>
                        <div className="mt-2">
                          <span
                            className={`text-xs px-2 py-1 rounded-full ${
                              rec.priority === "critical"
                                ? "bg-red-500/20 text-red-500"
                                : rec.priority === "high"
                                ? "bg-orange-500/20 text-orange-500"
                                : rec.priority === "medium"
                                ? "bg-yellow-500/20 text-yellow-500"
                                : "bg-blue-500/20 text-blue-500"
                            }`}
                          >
                            {rec.priority} priority
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    );
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          <div className="flex items-center space-x-4">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <h1 className="text-3xl font-bold">Loading Security Report...</h1>
          </div>
          <div className="space-y-4">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-[200px] w-full" />
            <div className="grid grid-cols-3 gap-4">
              <Skeleton className="h-[300px] w-full" />
              <Skeleton className="h-[300px] w-full" />
              <Skeleton className="h-[300px] w-full" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (scanStatus === "pending") {
    return (
      <div className="min-h-screen bg-background p-8">
        <div className="max-w-4xl mx-auto text-center">
          <div className="flex justify-center mb-6">
            <Clock className="h-16 w-16 text-blue-500 animate-pulse" />
          </div>
          <h2 className="text-2xl font-bold mb-4">Scan In Progress</h2>
          <p className="text-muted-foreground mb-6">
            Your security scan is currently being processed. This may take a few
            minutes.
          </p>
          <div className="flex items-center justify-center space-x-2 mb-6">
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
            <span>Checking status automatically...</span>
          </div>
          <div className="flex gap-4 justify-center">
            <button
              onClick={checkScanStatus}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Check Now
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (scanStatus === "failed") {
    return (
      <div className="min-h-screen bg-background p-8">
        <div className="max-w-4xl mx-auto text-center">
          <AlertTriangle className="h-16 w-16 mx-auto text-red-500 mb-4" />
          <h2 className="text-2xl font-bold mb-2">Scan Failed</h2>
          <p className="text-muted-foreground mb-6">
            The scan failed to complete. You can try again or contact support if
            the problem persists.
          </p>
          <div className="flex gap-4 justify-center">
            <button
              onClick={checkScanStatus}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh Status
            </button>
            <button
              onClick={retryScan}
              className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Retry Scan
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-background p-8">
        <div className="max-w-4xl mx-auto text-center">
          <AlertTriangle className="h-12 w-12 mx-auto text-yellow-500 mb-4" />
          <h2 className="text-2xl font-bold mb-2">Report Not Available</h2>
          <p className="text-muted-foreground mb-6">
            {error || "The requested report could not be loaded."}
          </p>
          <div className="flex gap-4 justify-center">
            <button
              onClick={checkScanStatus}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Try Again
            </button>
            {scanStatus === ("failed" as ScanStatus) && (
              <button
                onClick={retryScan}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Retry Scan
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (scanStatus === "completed" && report) {
    return (
      <div className="min-h-screen bg-background p-4 md:p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-2xl md:text-3xl font-bold">
                Security Report: {report.metadata.appName}
              </h1>
              <div className="text-muted-foreground mt-2 space-y-1 text-sm md:text-base">
                <p>Package: {report.metadata.packageName}</p>
                <p>
                  Version: {report.metadata.version} • Size:{" "}
                  {report.metadata.size}
                </p>
                <p className="font-mono text-xs md:text-sm break-all">
                  SHA256: {report.metadata.sha256}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2 bg-secondary/50 px-4 py-2 rounded-lg self-start md:self-auto">
              <Shield className="h-5 w-5 md:h-6 md:w-6 text-primary" />
              <span className="font-semibold text-sm md:text-base">
                Trust Forge Score: {report.tfScore}/100
              </span>
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Security Assessment</CardTitle>
              <CardDescription>
                Comprehensive analysis of security vulnerabilities and risks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Trust Forge Score</span>
                    <span>{report.tfScore}/100</span>
                  </div>
                  <Progress value={report.tfScore || 0} className="h-2" />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-red-500/10 rounded-lg">
                    <div className="text-red-500 font-bold text-2xl">
                      {report.vulnerabilities.high}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      High Risk
                    </div>
                  </div>
                  <div className="text-center p-4 bg-yellow-500/10 rounded-lg">
                    <div className="text-yellow-500 font-bold text-2xl">
                      {report.vulnerabilities.medium}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Medium Risk
                    </div>
                  </div>
                  <div className="text-center p-4 bg-green-500/10 rounded-lg">
                    <div className="text-green-500 font-bold text-2xl">
                      {report.vulnerabilities.low}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Low Risk
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Scan className="h-5 w-5" />
              MobSF Analysis
            </h2>
            {renderMobSFTabs()}
          </div>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Bug className="h-5 w-5" />
              VirusTotal
            </h2>
            {renderVirusTotalCard()}
          </div>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              MetaDefender Cloud
            </h2>
            {renderMetaDefenderCard()}
          </div>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Hybrid Analysis
            </h2>
            {renderHybridAnalysisCard()}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-4xl mx-auto text-center">
        <AlertTriangle className="h-12 w-12 mx-auto text-yellow-500 mb-4" />
        <h2 className="text-2xl font-bold mb-2">Unexpected State</h2>
        <p className="text-muted-foreground mb-6">
          The scan is in an unexpected state. Please try again.
        </p>
        <button
          onClick={checkScanStatus}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 flex items-center gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh Status
        </button>
      </div>
    </div>
  );
}
