"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useDropzone } from "react-dropzone";
import { Upload, FileType, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { scan } from "@/lib/api";

export default function ScanPage() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const router = useRouter();

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const uploadedFile = acceptedFiles[0];
    if (uploadedFile) {
      if (
        uploadedFile.name.endsWith(".apk") ||
        uploadedFile.name.endsWith(".ipa")
      ) {
        setFile(uploadedFile);
      } else {
        toast.error("Please upload an APK or IPA file");
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      "application/vnd.android.package-archive": [".apk"],
      "application/octet-stream": [".ipa"],
    },
    maxFiles: 1,
  });

  const startScan = async () => {
    if (!file) return;

    try {
      setIsUploading(true);
      const simulatedProgress = setInterval(() => {
        setUploadProgress((prev) => Math.min(prev + 10, 90));
      }, 500);

      const response = await scan.upload(file);
      clearInterval(simulatedProgress);
      setUploadProgress(100);

      toast.success("Scan initiated successfully");
      router.push(`/reports/${response.scanId}`);
    } catch (error) {
      toast.error("Failed to initiate scan");
      setUploadProgress(0);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background p-8 flex flex-col">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">New Security Scan</h1>
        <p className="text-muted-foreground mt-2">
          Upload your mobile application for security analysis
        </p>
      </div>

      <Card className="flex-1 flex flex-col">
        <CardHeader>
          <CardTitle>Upload Application</CardTitle>
          <CardDescription>
            Drag and drop your APK or IPA file here
          </CardDescription>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col">
          {!file ? (
            <div
              {...getRootProps()}
              className={`flex-1 border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors flex flex-col items-center justify-center
                ${
                  isDragActive
                    ? "border-primary bg-primary/5"
                    : "border-muted-foreground/25"
                }`}
            >
              <input {...getInputProps()} />
              <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                {isDragActive
                  ? "Drop the file here"
                  : "Drag & drop your file here, or click to select"}
              </p>
              <p className="text-sm text-muted-foreground/75 mt-2">
                Supported formats: APK, IPA
              </p>
            </div>
          ) : (
            <div className="flex-1 flex flex-col">
              <div className="flex-1 flex flex-col justify-center space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center space-x-4">
                    <FileType className="h-8 w-8 text-primary" />
                    <div>
                      <p className="font-medium">{file.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {(file.size / (1024 * 1024)).toFixed(2)} MB
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setFile(null)}
                    disabled={isUploading}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>

                {isUploading && (
                  <div className="space-y-2">
                    <Progress value={uploadProgress || 0} />
                    <p className="text-sm text-center text-muted-foreground">
                      Uploading... {uploadProgress}%
                    </p>
                  </div>
                )}
              </div>

              <Button
                className="w-full mt-4"
                onClick={startScan}
                disabled={isUploading}
              >
                {isUploading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Processing...
                  </>
                ) : (
                  "Start Scan"
                )}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
