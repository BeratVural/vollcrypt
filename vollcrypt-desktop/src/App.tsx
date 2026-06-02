import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save as tauriSave } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openUrl } from "@tauri-apps/plugin-opener";
import { listen } from "@tauri-apps/api/event";
import jsQR from "jsqr";
import "./App.css";

type Tab = "file" | "text" | "key";
type Mode = "password" | "recipient" | "threshold";
type Action = "encrypt" | "decrypt" | "verify" | "seal";

function ResizeHandles() {
  return (
    <>
      <div className="resize-handle top" onMouseDown={() => getCurrentWindow().startResizeDragging("North")} />
      <div className="resize-handle bottom" onMouseDown={() => getCurrentWindow().startResizeDragging("South")} />
      <div className="resize-handle left" onMouseDown={() => getCurrentWindow().startResizeDragging("West")} />
      <div className="resize-handle right" onMouseDown={() => getCurrentWindow().startResizeDragging("East")} />
      <div className="resize-handle top-left" onMouseDown={() => getCurrentWindow().startResizeDragging("NorthWest")} />
      <div className="resize-handle top-right" onMouseDown={() => getCurrentWindow().startResizeDragging("NorthEast")} />
      <div className="resize-handle bottom-left" onMouseDown={() => getCurrentWindow().startResizeDragging("SouthWest")} />
      <div className="resize-handle bottom-right" onMouseDown={() => getCurrentWindow().startResizeDragging("SouthEast")} />
    </>
  );
}

const getFilename = (filepath: string) => {
  const parts = filepath.split(/[/\\]/);
  return parts[parts.length - 1];
};

const formatBytes = (bytes: number) => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

const formatTime = (seconds: number) => {
  if (seconds <= 0) return "0s";
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (mins < 60) {
    return `${mins}m ${secs}s`;
  }
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}h ${remMins}m`;
};

const getDirectory = (filepath: string) => {
  const parts = filepath.split(/[/\\]/);
  parts.pop();
  return parts.join(filepath.includes("\\") ? "\\" : "/");
};

const joinPath = (dir: string, filename: string) => {
  const separator = dir.includes("\\") || filename.includes("\\") ? "\\" : "/";
  return dir.endsWith(separator) ? dir + filename : dir + separator + filename;
};

const deriveEncryptDest = (src: string, destDir: string) => {
  const filename = getFilename(src);
  if (destDir) {
    return joinPath(destDir, filename + ".voll");
  } else {
    return src + ".voll";
  }
};

const deriveDecryptDest = (src: string, destDir: string) => {
  const filename = getFilename(src);
  let outName = filename;
  if (filename.endsWith(".voll")) {
    let base = filename.substring(0, filename.length - 5);
    if (base.endsWith("_text")) {
      base = base.substring(0, base.length - 5) + ".txt";
    }
    outName = base;
  } else {
    outName = filename + ".dec";
  }

  if (destDir) {
    return joinPath(destDir, outName);
  } else {
    const dir = getDirectory(src);
    return joinPath(dir, outName);
  }
};

function App() {
  const clipboardTimerRef = useRef<any>(null);
  const handleMinimize = () => {
    getCurrentWindow().minimize();
  };

  const handleClose = () => {
    getCurrentWindow().close();
  };

  const handleOpenGithub = async () => {
    try {
      await openUrl("https://github.com/BeratVural/vollcrypt");
    } catch (err: any) {
      showStatus("error", `Failed to open GitHub: ${err}`);
    }
  };
  const [activeTab, setActiveTab] = useState<Tab>("file");
  const [activeMode, setActiveMode] = useState<Mode>("password");
  const [fileAction, setFileAction] = useState<Action>("encrypt");
  const [textAction, setTextAction] = useState<Action>("encrypt");

  // File states
  const [sourceFiles, setSourceFiles] = useState<string[]>([]);
  const [destFile, setDestFile] = useState("");
  const [password, setPassword] = useState("");
  const [kdfChoice, setKdfChoice] = useState("Argon2id");
  const [recipientKey, setRecipientKey] = useState("");
  const [replaceOriginal, setReplaceOriginal] = useState(false);

  // Progress states
  const [fileProgress, setFileProgress] = useState<{
    filePath: string;
    bytesProcessed: number;
    totalBytes: number;
    percentage: number;
    eta: number | null;
  } | null>(null);
  const currentFileStartTimeRef = useRef<number | null>(null);

  useEffect(() => {
    if (sourceFiles.length === 1) {
      const sourceFile = sourceFiles[0];
      if (fileAction === "encrypt") {
        setDestFile(sourceFile + ".voll");
      } else if (fileAction === "decrypt") {
        if (sourceFile.endsWith(".voll")) {
          let base = sourceFile.substring(0, sourceFile.length - 5);
          if (base.endsWith("_text")) {
            base = base.substring(0, base.length - 5) + ".txt";
          }
          setDestFile(base);
        } else {
          if (sourceFile.endsWith("_text")) {
            setDestFile(sourceFile.substring(0, sourceFile.length - 5) + ".txt");
          } else {
            setDestFile(sourceFile + ".dec");
          }
        }
      }
    } else if (sourceFiles.length > 1) {
      setDestFile("");
    }
  }, [replaceOriginal, sourceFiles, fileAction]);

  useEffect(() => {
    if (activeMode === "password" || activeMode === "threshold") {
      setVerifySignaturePolicy("optional");
    } else {
      setVerifySignaturePolicy("required");
    }
  }, [activeMode]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;

    listen<any>("file-progress", (event) => {
      const payload = event.payload;
      if (!payload) return;
      const { filePath, bytesProcessed, totalBytes } = payload;

      const startTime = currentFileStartTimeRef.current;
      let eta: number | null = null;
      if (startTime && bytesProcessed > 0) {
        const elapsedSeconds = (Date.now() - startTime) / 1000;
        if (elapsedSeconds > 0) {
          const speed = bytesProcessed / elapsedSeconds;
          const remainingBytes = totalBytes - bytesProcessed;
          if (speed > 0) {
            eta = Math.ceil(remainingBytes / speed);
          }
        }
      }

      const percentage = totalBytes > 0 ? Math.round((bytesProcessed / totalBytes) * 100) : 0;

      setFileProgress({
        filePath,
        bytesProcessed,
        totalBytes,
        percentage,
        eta,
      });
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  // Verify states
  const [verifyReleaseMode, setVerifyReleaseMode] = useState("verified");
  const [verifySignaturePolicy, setVerifySignaturePolicy] = useState("required");
  const [verifyRollbackPin, setVerifyRollbackPin] = useState("");
  const [verifyFounderAnchor, setVerifyFounderAnchor] = useState(true);
  const [verifyOnTamper, setVerifyOnTamper] = useState("abort");
  const [verifyReport, setVerifyReport] = useState<string | null>(null);
  const [sealedInspection, setSealedInspection] = useState<any | null>(null);

  // Seal states
  const [sealMode, setSealMode] = useState("seal");
  const [sealReason, setSealReason] = useState("");
  const [sealConfirmText, setSealConfirmText] = useState("");
  const [sealSignEnabled, setSealSignEnabled] = useState(false);
  const [sealSignKind, setSealSignKind] = useState("plain");
  const [sealSignerPk, setSealSignerPk] = useState("");
  const [sealSignerSk, setSealSignerSk] = useState("");
  const [sealKeyLogId, setSealKeyLogId] = useState("");

  // Text states
  const [inputText, setInputText] = useState("");
  const [outputText, setOutputText] = useState("");

  // Key generator states
  const [generatedPk, setGeneratedPk] = useState("");
  const [generatedSk, setGeneratedSk] = useState("");

  // Threshold SSS states
  const [thresholdT, setThresholdT] = useState<number>(2);
  const [thresholdN, setThresholdN] = useState<number>(3);
  const [inputShares, setInputShares] = useState("");
  const [generatedShares, setGeneratedShares] = useState<string[] | null>(null);

  // Platform and EULA states
  const [platformInfo, setPlatformInfo] = useState<{ os: string; arch: string }>({ os: "", arch: "" });
  const [isEulaApproved, setIsEulaApproved] = useState<boolean>(true);
  const [eulaChecked, setEulaChecked] = useState(false);
  // Splash states
  const [showSplash, setShowSplash] = useState(true);
  const [typedLength, setTypedLength] = useState(0);
  const [isSplashDone, setIsSplashDone] = useState(false);

  // Settings States
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [performanceProfile, setPerformanceProfile] = useState(() => localStorage.getItem("vollcrypt_perf_profile") || "balanced");
  const [clipboardClearEnabled, setClipboardClearEnabled] = useState(() => localStorage.getItem("vollcrypt_clip_enabled") !== "false");
  const [clipboardClearDelay, setClipboardClearDelay] = useState(() => Number(localStorage.getItem("vollcrypt_clip_delay") || "30"));

  // QR Code States
  const [activeQrShare, setActiveQrShare] = useState<string | null>(null);
  const [activeQrSvg, setActiveQrSvg] = useState<string | null>(null);
  const [activeQrTitle, setActiveQrTitle] = useState<string | null>(null);

  const handleShowQr = async (share: string, title: string) => {
    try {
      const svg: string = await invoke("generate_share_qr", { share });
      setActiveQrShare(share);
      setActiveQrSvg(svg);
      setActiveQrTitle(title);
    } catch (err: any) {
      showStatus("error", `Failed to generate QR code: ${err}`);
    }
  };

  const scanQrFromImage = (img: HTMLImageElement): string | null => {
    const sizes = [
      { w: img.width, h: img.height },
      { w: 800, h: Math.round(img.height * (800 / img.width)) },
      { w: 1200, h: Math.round(img.height * (1200 / img.width)) }
    ];

    const uniqueSizes = [];
    const seen = new Set<string>();
    for (const size of sizes) {
      if (size.w <= 0 || size.h <= 0) continue;
      const key = `${size.w}x${size.h}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueSizes.push(size);
      }
    }

    for (const size of uniqueSizes) {
      const canvas = document.createElement("canvas");
      canvas.width = size.w;
      canvas.height = size.h;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.drawImage(img, 0, 0, size.w, size.h);
        try {
          const imageData = ctx.getImageData(0, 0, size.w, size.h);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code && code.data && code.data.trim()) {
            return code.data.trim();
          }
        } catch (err) {
          console.error("Error running jsQR on size", size, err);
        }
      }
    }
    return null;
  };

  const handleDownloadQr = () => {
    if (!activeQrSvg || !activeQrTitle) return;

    const base64Svg = btoa(unescape(encodeURIComponent(activeQrSvg)));
    const url = `data:image/svg+xml;base64,${base64Svg}`;

    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = 512;
      canvas.height = 512;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 16, 16, canvas.width - 32, canvas.height - 32);

        const pngUrl = canvas.toDataURL("image/png");
        const downloadLink = document.createElement("a");
        downloadLink.href = pngUrl;
        downloadLink.download = `${activeQrTitle.toLowerCase().replace(/[^a-z0-9]/g, "_")}_qr.png`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
      }
    };
    img.src = url;
  };

  const [isQrDragOver, setIsQrDragOver] = useState(false);

  const handleQrDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsQrDragOver(true);
  };

  const handleQrDragLeave = () => {
    setIsQrDragOver(false);
  };

  const handleQrDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsQrDragOver(false);
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (event) => {
        if (!event.target || !event.target.result) return;
        const img = new Image();
        img.onload = () => {
          const decoded = scanQrFromImage(img);
          if (decoded) {
            if (decoded.startsWith("vcs_")) {
              setInputShares((prev) => {
                const current = prev.trim();
                if (current.includes(decoded)) {
                  showStatus("info", `Share is already loaded: ${decoded.substring(0, 15)}...`);
                  return prev;
                }
                showStatus("success", `Successfully decoded share: ${decoded.substring(0, 15)}...`);
                return current ? `${current}\n${decoded}` : decoded;
              });
            } else {
              showStatus("error", `Scanned QR code does not contain a valid SSS share (must start with vcs_).`);
            }
          } else {
            showStatus("error", `Could not find a valid QR code in the image: ${file.name}`);
          }
        };
        img.src = event.target.result as string;
      };
      reader.readAsDataURL(file);
    });
  };

  const handleQrUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (event) => {
        if (!event.target || !event.target.result) return;
        const img = new Image();
        img.onload = () => {
          const decoded = scanQrFromImage(img);
          if (decoded) {
            if (decoded.startsWith("vcs_")) {
              setInputShares((prev) => {
                const current = prev.trim();
                if (current.includes(decoded)) {
                  showStatus("info", `Share is already loaded: ${decoded.substring(0, 15)}...`);
                  return prev;
                }
                showStatus("success", `Successfully decoded share: ${decoded.substring(0, 15)}...`);
                return current ? `${current}\n${decoded}` : decoded;
              });
            } else {
              showStatus("error", `Scanned QR code does not contain a valid SSS share (must start with vcs_).`);
            }
          } else {
            showStatus("error", `Could not find a valid QR code in the image: ${file.name}`);
          }
        };
        img.src = event.target.result as string;
      };
      reader.readAsDataURL(file);
    });

    e.target.value = "";
  };

  useEffect(() => {
    localStorage.setItem("vollcrypt_perf_profile", performanceProfile);
  }, [performanceProfile]);

  useEffect(() => {
    localStorage.setItem("vollcrypt_clip_enabled", clipboardClearEnabled.toString());
  }, [clipboardClearEnabled]);

  useEffect(() => {
    localStorage.setItem("vollcrypt_clip_delay", clipboardClearDelay.toString());
  }, [clipboardClearDelay]);

  useEffect(() => {
    let timeoutId: any;
    const totalLength = 20;

    const typeNext = (currentLength: number) => {
      if (currentLength < totalLength) {
        let delay = 70; // powered by
        if (currentLength >= 11 && currentLength < 15) {
          delay = 140; // VOLL
        } else if (currentLength >= 15) {
          delay = 180; // crypt (deliberate cursive writing effect)
        }
        timeoutId = setTimeout(() => {
          setTypedLength(currentLength + 1);
          typeNext(currentLength + 1);
        }, delay);
      } else {
        // Hold the completed logo on screen for 1000ms
        timeoutId = setTimeout(() => {
          setIsSplashDone(true); // Start fade-out transition (200ms)
          timeoutId = setTimeout(() => {
            setShowSplash(false); // Unmount once faded out
          }, 200);
        }, 1000);
      }
    };

    typeNext(0);

    return () => clearTimeout(timeoutId);
  }, []);

  const fullText = "powered by VOLLcrypt";
  const displayPowered = fullText.slice(0, Math.min(typedLength, 11));
  const displayVoll = typedLength > 11 ? fullText.slice(11, Math.min(typedLength, 15)) : "";
  const displayCrypt = typedLength > 15 ? fullText.slice(15, typedLength) : "";

  useEffect(() => {
    invoke<{ os: string; arch: string }>("get_platform_info")
      .then(info => {
        setPlatformInfo(info);
        if (info.os === "macOS" || info.os === "Linux") {
          const approved = localStorage.getItem("vollcrypt_eula_approved") === "true";
          if (!approved) {
            setIsEulaApproved(false);
          }
        }
      })
      .catch(err => console.error("Failed to get platform info:", err));

    // Register operating system right-click context menu integration
    invoke("register_context_menu").catch(err => {
      console.warn("Failed to register context menu:", err);
    });

    // Check if the application was launched with files (e.g. from context menu)
    invoke("get_cli_args").then((args: any) => {
      if (Array.isArray(args) && args.length > 0) {
        const files = args.filter(arg => !arg.startsWith("-"));
        if (files.length > 0) {
          setSourceFiles(files);
          setFileAction("encrypt");
          setActiveTab("file");
        }
      }
    }).catch(err => {
      console.warn("Failed to read CLI arguments:", err);
    });
  }, []);

  // UI state
  const [status, setStatus] = useState<{ type: "success" | "error" | "info"; msg: string } | null>(null);
  const [loading, setLoading] = useState(false);

  const showStatus = (type: "success" | "error" | "info", msg: string) => {
    setStatus({ type, msg });
    if (type === "success") {
      setTimeout(() => setStatus(null), 5000);
    }
  };

  const handlePickSource = async () => {
    try {
      const files = await open({
        multiple: true,
        directory: false,
        title: "Select Source File(s)",
      });
      if (files) {
        const selected = Array.isArray(files) ? files : [files];
        setSourceFiles(selected);
      }
    } catch (err: any) {
      showStatus("error", `File selection failed: ${err}`);
    }
  };

  const handlePickDest = async () => {
    try {
      if (sourceFiles.length <= 1) {
        const file = await tauriSave({
          title: "Select Destination Path",
          defaultPath: destFile || undefined,
        });
        if (file) {
          setDestFile(file);
        }
      } else {
        const directory = await open({
          multiple: false,
          directory: true,
          title: "Select Destination Directory",
        });
        if (typeof directory === "string" && directory) {
          setDestFile(directory);
        }
      }
    } catch (err: any) {
      showStatus("error", `Destination selection failed: ${err}`);
    }
  };

  const handleFileProcess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (sourceFiles.length === 0) {
      showStatus("error", "At least one source file path is required.");
      return;
    }
    if ((fileAction === "encrypt" || fileAction === "decrypt") && sourceFiles.length === 1 && !destFile) {
      showStatus("error", "Source and destination paths are required.");
      return;
    }

    setLoading(true);
    setVerifyReport(null);
    setSealedInspection(null);
    setFileProgress(null);

    const filesToProcess = [...sourceFiles];
    let successCount = 0;
    const errors: string[] = [];

    for (let i = 0; i < filesToProcess.length; i++) {
      const currentFile = filesToProcess[i];
      const currentFilename = getFilename(currentFile);
      
      currentFileStartTimeRef.current = Date.now();
      setFileProgress({
        filePath: currentFile,
        bytesProcessed: 0,
        totalBytes: 0,
        percentage: 0,
        eta: null,
      });

      setStatus({ 
        type: "info", 
        msg: `Processing file ${i + 1} of ${filesToProcess.length}: ${currentFilename}...` 
      });

      try {
        let currentDest = "";
        if (fileAction === "encrypt" || fileAction === "decrypt") {
          if (filesToProcess.length === 1 && destFile) {
            currentDest = destFile;
          } else {
            currentDest = fileAction === "encrypt" 
              ? deriveEncryptDest(currentFile, destFile) 
              : deriveDecryptDest(currentFile, destFile);
          }
        }

        if (fileAction === "encrypt") {
          if (activeMode === "password") {
            if (!password) throw new Error("Encryption password is required.");
            await invoke("encrypt_file_password", {
              sourcePath: currentFile,
              destPath: currentDest,
              password,
              kdfChoice,
              perfProfile: performanceProfile,
              deleteSource: replaceOriginal,
            });
          } else if (activeMode === "recipient") {
            if (!recipientKey) throw new Error("Recipient Public Key is required.");
            await invoke("encrypt_file_recipient", {
              sourcePath: currentFile,
              destPath: currentDest,
              recipientPkHex: recipientKey.trim(),
              perfProfile: performanceProfile,
              deleteSource: replaceOriginal,
            });
          } else {
            if (thresholdT < 2) throw new Error("Threshold (t) must be at least 2.");
            if (thresholdN < thresholdT) throw new Error("Total shares (n) must be greater than or equal to threshold (t).");
            const shares: string[] = await invoke("encrypt_file_threshold", {
              sourcePath: currentFile,
              destPath: currentDest,
              t: thresholdT,
              n: thresholdN,
              perfProfile: performanceProfile,
              deleteSource: replaceOriginal,
            });
            setGeneratedShares(shares);
          }
        } else if (fileAction === "decrypt") {
          let shieldPolicy = null;
          if (verifyReleaseMode || verifySignaturePolicy) {
            shieldPolicy = {
              releaseMode: verifyReleaseMode,
              signature: verifySignaturePolicy,
              rollbackPin: verifyRollbackPin ? parseInt(verifyRollbackPin, 10) : null,
              founderAnchor: verifyFounderAnchor,
              onTamper: verifyOnTamper,
            };
          }
          if (activeMode === "password") {
            if (!password) throw new Error("Decryption password is required.");
            await invoke("decrypt_file_password", {
              sourcePath: currentFile,
              destPath: currentDest,
              password,
              shield: shieldPolicy,
              perfProfile: performanceProfile,
              deleteSource: false,
            });
          } else if (activeMode === "recipient") {
            if (!recipientKey) throw new Error("Recipient Secret Key is required.");
            await invoke("decrypt_file_recipient", {
              sourcePath: currentFile,
              destPath: currentDest,
              recipientSkHex: recipientKey.trim(),
              shield: shieldPolicy,
              perfProfile: performanceProfile,
              deleteSource: false,
            });
          } else {
            const parsedShares = inputShares
              .split("\n")
              .map(s => s.trim())
              .filter(s => s.length > 0);
            if (parsedShares.length === 0) throw new Error("Please paste at least t shares.");
            await invoke("decrypt_file_threshold", {
              sourcePath: currentFile,
              destPath: currentDest,
              shares: parsedShares,
              shield: shieldPolicy,
              perfProfile: performanceProfile,
              deleteSource: false,
            });
          }
        } else if (fileAction === "verify") {
          const policy = {
            releaseMode: verifyReleaseMode,
            signature: verifySignaturePolicy,
            rollbackPin: verifyRollbackPin ? parseInt(verifyRollbackPin, 10) : null,
            founderAnchor: verifyFounderAnchor,
            onTamper: verifyOnTamper,
          };
          const report: string = await invoke("verify_container_file", {
            path: currentFile,
            policy,
          });
          setVerifyReport(report);
          if (report === "ContainerSealed") {
            showStatus("info", `Verification (${currentFilename}): Container is Sealed.`);
            try {
              const inspectRes = await invoke("inspect_sealed_file", { path: currentFile });
              setSealedInspection(inspectRes);
            } catch (inspectErr) {
              console.error("Failed to inspect sealed container:", inspectErr);
            }
          } else if (report === "Success" || report.includes("Success")) {
            // Success
          } else {
            throw new Error(report);
          }
        } else if (fileAction === "seal") {
          if (sealConfirmText !== "SEAL") {
            throw new Error("Please type SEAL to confirm this irreversible action.");
          }
          let signInfo = null;
          if (sealSignEnabled) {
            if (!sealSignerPk || !sealSignerSk || !sealKeyLogId) {
              throw new Error("Signing keys and Key Log ID are required when signing the sealed marker.");
            }
            signInfo = {
              kind: sealSignKind,
              signerPk: sealSignerPk.trim(),
              signerSk: sealSignerSk.trim(),
              keyLogId: sealKeyLogId.trim(),
              timestamp: Math.floor(Date.now() / 1000),
            };
          }
          await invoke("seal_file", {
            path: currentFile,
            mode: sealMode,
            reason: sealReason || null,
            signInfo,
          });
        }
        successCount++;
      } catch (err: any) {
        const errorMsg = err.message || String(err);
        errors.push(`${currentFilename}: ${errorMsg}`);
      }
    }

    if (errors.length === 0) {
      showStatus("success", `Successfully processed all ${filesToProcess.length} file(s).`);
    } else if (successCount > 0) {
      showStatus("info", `Completed ${successCount} of ${filesToProcess.length} file(s). Errors: ${errors.join("; ")}`);
    } else {
      showStatus("error", `Failed processing file(s): ${errors.join("; ")}`);
    }
    setFileProgress(null);
    currentFileStartTimeRef.current = null;
    setLoading(false);
  };

  const handleTextProcess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText) {
      showStatus("error", "Input text area cannot be empty.");
      return;
    }

    setLoading(true);
    setStatus(null);
    setOutputText("");
    setGeneratedShares(null);

    try {
      if (textAction === "encrypt") {
        let result = "";
        if (activeMode === "password") {
          if (!password) throw new Error("Password is required for encryption.");
          result = await invoke("encrypt_text_password", {
            text: inputText,
            password,
            kdfChoice,
            perfProfile: performanceProfile,
          });
        } else if (activeMode === "recipient") {
          if (!recipientKey) throw new Error("Recipient Public Key is required.");
          result = await invoke("encrypt_text_recipient", {
            text: inputText,
            recipientPkHex: recipientKey.trim(),
          });
        } else {
          if (thresholdT < 2) throw new Error("Threshold (t) must be at least 2.");
          if (thresholdN < thresholdT) throw new Error("Total shares (n) must be greater than or equal to threshold (t).");
          const res: { ciphertextHex: string; shares: string[] } = await invoke("encrypt_text_threshold", {
            text: inputText,
            t: thresholdT,
            n: thresholdN,
          });
          result = res.ciphertextHex;
          setGeneratedShares(res.shares);
        }
        setOutputText(result);
        showStatus("success", "Text encrypted successfully.");
      } else {
        let result = "";
        if (activeMode === "password") {
          if (!password) throw new Error("Password is required for decryption.");
          result = await invoke("decrypt_text_password", {
            ciphertextHex: inputText.trim(),
            password,
          });
        } else if (activeMode === "recipient") {
          if (!recipientKey) throw new Error("Secret Key is required for decryption.");
          result = await invoke("decrypt_text_recipient", {
            ciphertextHex: inputText.trim(),
            recipientSkHex: recipientKey.trim(),
          });
        } else {
          const parsedShares = inputShares
            .split("\n")
            .map(s => s.trim())
            .filter(s => s.length > 0);
          if (parsedShares.length === 0) throw new Error("Please paste at least t shares.");
          result = await invoke("decrypt_text_threshold", {
            ciphertextHex: inputText.trim(),
            shares: parsedShares,
          });
        }
        setOutputText(result);
        showStatus("success", "Text decrypted successfully.");
      }
    } catch (err: any) {
      showStatus("error", err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateKeys = async () => {
    setLoading(true);
    setStatus(null);
    try {
      const keys: any = await invoke("generate_keypair");
      setGeneratedPk(keys.public_key);
      setGeneratedSk(keys.secret_key);
      showStatus("success", "Hybrid keypair generated successfully.");
    } catch (err: any) {
      showStatus("error", `Key generation failed: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const saveTextToFile = async (type: string, content: string, defaultName: string) => {
    try {
      const file = await tauriSave({
        title: `Save ${type}`,
        defaultPath: defaultName,
      });
      if (file) {
        await invoke("save_text_file", { path: file, content });
        showStatus("success", `${type} saved to file.`);
      }
    } catch (err: any) {
      showStatus("error", `Failed to save file: ${err}`);
    }
  };

  const loadKeyFromFile = async () => {
    try {
      const file = await open({
        multiple: false,
        directory: false,
        title: "Load Public/Secret Key File",
      });
      if (typeof file === "string" && file) {
        const content: string = await invoke("load_text_file", { path: file });
        setRecipientKey(content.trim());
        showStatus("success", "Key loaded from file.");
      }
    } catch (err: any) {
      showStatus("error", `Failed to load key: ${err}`);
    }
  };

  const saveBinToFile = async (type: string, hexContent: string, defaultName: string) => {
    try {
      const file = await tauriSave({
        title: `Save ${type}`,
        defaultPath: defaultName,
      });
      if (file) {
        await invoke("save_bin_file", { path: file, hexContent });
        showStatus("success", `${type} saved to file.`);
      }
    } catch (err: any) {
      showStatus("error", `Failed to save file: ${err}`);
    }
  };

  const loadBinFromFile = async () => {
    try {
      const file = await open({
        multiple: false,
        directory: false,
        title: "Select Encrypted Vollcrypt File",
      });
      if (typeof file === "string" && file) {
        const content: string = await invoke("load_bin_file", { path: file });
        setInputText(content);
        showStatus("success", "Encrypted file loaded and converted to hex.");
      }
    } catch (err: any) {
      showStatus("error", `Failed to load encrypted file: ${err}`);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showStatus("success", `${label} copied to clipboard.`);

    if (clipboardTimerRef.current) {
      clearTimeout(clipboardTimerRef.current);
    }

    if (clipboardClearEnabled && clipboardClearDelay > 0) {
      clipboardTimerRef.current = setTimeout(async () => {
        try {
          const currentText = await navigator.clipboard.readText();
          if (currentText === text) {
            await navigator.clipboard.writeText("");
            showStatus("info", "Clipboard automatically cleared for security.");
          }
        } catch (e) {
          console.warn("Failed to read clipboard for clearing:", e);
        }
      }, clipboardClearDelay * 1000);
    }
  };

  if (showSplash) {
    return (
      <div className="window-frame">
        <ResizeHandles />
        <div className={`splash-screen ${isSplashDone ? "fade-out" : ""}`}>
          <div className="splash-content">
            <span className="splash-powered">{displayPowered}</span>
            {typedLength > 11 && (
              <span className="splash-voll">{displayVoll}</span>
            )}
            {typedLength > 15 && (
              <span className="splash-crypt">{displayCrypt}</span>
            )}
            <span className="splash-cursor">|</span>
          </div>
        </div>
      </div>
    );
  }

  if (!isEulaApproved) {
    return (
      <div className="window-frame">
        <ResizeHandles />
        {/* Custom Titlebar */}
        <div className="custom-titlebar" data-tauri-drag-region>
          <div className="titlebar-brand" data-tauri-drag-region>
            <span className="brand-text" data-tauri-drag-region>
              <span className="brand-voll" data-tauri-drag-region>VOLL</span><span className="brand-crypt" data-tauri-drag-region>crypt</span>
            </span>
            <span className="titlebar-version" data-tauri-drag-region>EULA Consent</span>
          </div>
          <div className="titlebar-controls">
            <button type="button" className="titlebar-btn close" onClick={handleClose} title="Close">✕</button>
          </div>
        </div>

        <div className="app-container" style={{ display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center" }}>
          <div className="main-card" style={{ maxWidth: "580px", padding: "24px" }}>
            <h2 style={{ fontSize: "14px", fontWeight: "700", color: "#ffffff", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px", fontFamily: "JetBrains Mono, monospace" }}>
              End User License Agreement (EULA)
            </h2>
            <p style={{ fontSize: "11px", color: "#a1a1aa", marginBottom: "14px", lineHeight: "1.4" }}>
              Welcome to VOLLcrypt. Since you are running on {platformInfo.os || "a Unix platform"} (which skips the Windows setup wizard), you must review and accept our zero-knowledge Privacy Policy and EULA to proceed.
            </p>

            <div style={{
              backgroundColor: "#141416",
              border: "1px solid #1f1f23",
              borderRadius: "6px",
              padding: "12px",
              height: "220px",
              overflowY: "scroll",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "10px",
              color: "#8b8d99",
              lineHeight: "1.5",
              whiteSpace: "pre-wrap",
              userSelect: "text"
            }}>
              {EULA_TEXT}
            </div>

            <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", marginTop: "16px", marginBottom: "20px" }}>
              <input
                type="checkbox"
                id="eulaCheckbox"
                checked={eulaChecked}
                onChange={(e) => setEulaChecked(e.target.checked)}
                style={{ accentColor: "#f97316", marginTop: "2px", cursor: "pointer" }}
              />
              <label htmlFor="eulaCheckbox" style={{ marginBottom: 0, textTransform: "none", cursor: "pointer", fontSize: "11px", color: "#e4e4e7", userSelect: "none", lineHeight: "1.4" }}>
                I have read, understood, and agree to be bound by the End User License Agreement and Privacy Policy, including the warning that lost passwords/keys are strictly unrecoverable.
              </label>
            </div>

            <button
              type="button"
              className="btn-primary"
              disabled={!eulaChecked}
              onClick={() => {
                localStorage.setItem("vollcrypt_eula_approved", "true");
                setIsEulaApproved(true);
              }}
            >
              Accept & Continue
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="window-frame">
      <ResizeHandles />
      {/* Custom Titlebar */}
      <div className="custom-titlebar" data-tauri-drag-region>
        <div className="titlebar-brand" data-tauri-drag-region>
          <span className="brand-text" data-tauri-drag-region>
            <span className="brand-voll" data-tauri-drag-region>VOLL</span><span className="brand-crypt" data-tauri-drag-region>crypt</span>
          </span>
          <span className="titlebar-version" data-tauri-drag-region>
            v0.2.0 {platformInfo.os && platformInfo.arch ? `(${platformInfo.os} ${platformInfo.arch})` : ""}
          </span>
        </div>
        <div className="titlebar-controls">
          <button
            type="button"
            className="titlebar-btn github-btn"
            onClick={handleOpenGithub}
            title="Open GitHub Repository"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
              <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
            </svg>
          </button>
          <button
            type="button"
            className="titlebar-btn settings-btn"
            onClick={() => setShowSettingsModal(true)}
            title="Settings"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
          <button type="button" className="titlebar-btn" onClick={handleMinimize} title="Minimize">—</button>
          <button type="button" className="titlebar-btn close" onClick={handleClose} title="Close">✕</button>
        </div>
      </div>

      <div className="app-container">
        <div className="main-card">

        {/* Tab Selector */}
        <nav className="nav-menu">
          <div
            className={`nav-item ${activeTab === "file" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("file");
              setPassword("");
              setRecipientKey("");
              setSourceFiles([]);
              setDestFile("");
              setInputText("");
              setOutputText("");
              setInputShares("");
              setGeneratedShares(null);
              setThresholdT(2);
              setThresholdN(3);
              setStatus(null);
            }}
          >
            File
          </div>
          <div
            className={`nav-item ${activeTab === "text" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("text");
              setPassword("");
              setRecipientKey("");
              setSourceFiles([]);
              setDestFile("");
              setInputText("");
              setOutputText("");
              setInputShares("");
              setGeneratedShares(null);
              setThresholdT(2);
              setThresholdN(3);
              setStatus(null);
            }}
          >
            Text
          </div>
          <div
            className={`nav-item ${activeTab === "key" ? "active" : ""}`}
            style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}
            onClick={() => {
              setActiveTab("key");
              setPassword("");
              setRecipientKey("");
              setSourceFiles([]);
              setDestFile("");
              setInputText("");
              setOutputText("");
              setInputShares("");
              setGeneratedShares(null);
              setThresholdT(2);
              setThresholdN(3);
              setStatus(null);
            }}
          >
            Keypair
            <div className="info-tooltip-wrapper" style={{ marginLeft: "2px" }}>
              <span className="info-icon">i</span>
              <div className="tooltip-content right-aligned">
                <strong>Keypair Generation:</strong>
                Create quantum-resistant hybrid keypairs combining ML-KEM-768 with classical X25519.
              </div>
            </div>
          </div>
        </nav>

        {/* File Tab */}
        {activeTab === "file" && (
          <form onSubmit={handleFileProcess}>
            <div className="settings-row" style={{ flexDirection: "column", gap: "12px", alignItems: "stretch" }}>
              <div className="segmented-control" style={{ display: "flex", width: "100%" }}>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "encrypt" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setFileAction("encrypt");
                    setSourceFiles([]);
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                    setVerifyReport(null);
                    setSealedInspection(null);
                  }}
                >
                  Encrypt
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Encrypt:</strong>
                      Secures a file by wrapping it in an encrypted container.
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "decrypt" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setFileAction("decrypt");
                    setSourceFiles([]);
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                    setVerifyReport(null);
                    setSealedInspection(null);
                  }}
                >
                  Decrypt
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Decrypt:</strong>
                      Restores the original file using the correct wrapping key.
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "verify" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setFileAction("verify");
                    setSourceFiles([]);
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                    setVerifyReport(null);
                    setSealedInspection(null);
                  }}
                >
                  Verify
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Verify:</strong>
                      Parses the container headers and verifies the cryptographic signature log without exposing the data payload.
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "seal" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setFileAction("seal");
                    setSourceFiles([]);
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                    setVerifyReport(null);
                    setSealedInspection(null);
                  }}
                >
                  Seal / Purge
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Seal / Purge:</strong>
                      Sovereignly locks the container, permanently destroying wrapper keys to prevent any future decryption.
                    </div>
                  </div>
                </button>
              </div>

              {(fileAction === "encrypt" || fileAction === "decrypt") && (
                <div className="segmented-control" style={{ display: "flex", width: "100%" }}>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "password" ? "active" : ""}`}
                    style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                    onClick={() => {
                      setActiveMode("password");
                      setPassword("");
                      setRecipientKey("");
                      setInputShares("");
                      setGeneratedShares(null);
                      setStatus(null);
                    }}
                  >
                    Password
                    <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Password Mode:</strong>
                        Secures the container using a master password with Argon2id or PBKDF2 key derivation.
                      </div>
                    </div>
                  </button>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "recipient" ? "active" : ""}`}
                    style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                    onClick={() => {
                      setActiveMode("recipient");
                      setPassword("");
                      setRecipientKey("");
                      setInputShares("");
                      setGeneratedShares(null);
                      setStatus(null);
                    }}
                  >
                    Hybrid KEM
                    <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Hybrid KEM Mode:</strong>
                        Utilizes post-quantum ML-KEM-768 combined with classical X25519 public-key cryptography to seal for a specific recipient keypair.
                      </div>
                    </div>
                  </button>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "threshold" ? "active" : ""}`}
                    style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                    onClick={() => {
                      setActiveMode("threshold");
                      setPassword("");
                      setRecipientKey("");
                      setInputShares("");
                      setGeneratedShares(null);
                      setStatus(null);
                    }}
                  >
                    Threshold (t-of-n)
                    <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Threshold Mode:</strong>
                        Splits the access key into multiple independent SSS shares, requiring at least 't' shares to decrypt.
                      </div>
                    </div>
                  </button>
                </div>
              )}

            </div>

            <div className="form-group">
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                <label style={{ marginBottom: 0 }}>Source File(s)</label>
                <div className="info-tooltip-wrapper">
                  <span className="info-icon">i</span>
                  <div className="tooltip-content">
                    <strong>Source File(s):</strong>
                    The input file(s) for the cryptographic operation.
                    <ul>
                      <li>For Encrypt: Choose regular files you wish to secure.</li>
                      <li>For Decrypt / Verify / Seal: Choose previously encrypted VOLL containers (.voll files).</li>
                    </ul>
                  </div>
                </div>
              </div>
              <div className="file-picker">
                <div className="file-path" title={sourceFiles.join("\n")}>
                  {sourceFiles.length > 0
                    ? sourceFiles.length === 1
                      ? sourceFiles[0]
                      : `${sourceFiles.length} file(s) selected...`
                    : "No file(s) selected..."}
                </div>
                <button type="button" className="file-picker-btn" onClick={handlePickSource}>
                  Browse
                </button>
              </div>
              <div className="field-helper">Choose the target file container(s) to process.</div>
            </div>

            {fileAction === "encrypt" && (
              <div className="form-group" style={{ marginBottom: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "4px" }}>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={replaceOriginal}
                      onChange={(e) => setReplaceOriginal(e.target.checked)}
                    />
                    <span className="slider"></span>
                  </label>
                  <span style={{ fontSize: "11px", color: "#e4e4e7", userSelect: "none" }}>
                    Replace original file (delete source after successful completion)
                  </span>
                </div>
              </div>
            )}

            {((fileAction === "encrypt" && !replaceOriginal) || fileAction === "decrypt") && (
              <div className="form-group">
                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                  <label style={{ marginBottom: 0 }}>
                    {sourceFiles.length > 1 ? "Destination Directory" : "Destination File"}
                  </label>
                  <div className="info-tooltip-wrapper">
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      {sourceFiles.length > 1 ? (
                        <>
                          <strong>Destination Directory:</strong>
                          The folder where all processed files will be saved.
                          <ul>
                            <li>Leave empty to save in the same directory as each source file.</li>
                            <li>Ensure you have write permissions for the selected directory.</li>
                          </ul>
                        </>
                      ) : (
                        <>
                          <strong>Destination File:</strong>
                          The output path where the processed file will be saved.
                          <ul>
                            <li>Make sure you have write permissions for the selected directory.</li>
                            <li>Ensure you do not overwrite important data files.</li>
                          </ul>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <div className="file-picker">
                  <div className="file-path">
                    {destFile || (sourceFiles.length > 1 ? "Same directory as source files..." : "Select save path...")}
                  </div>
                  <button type="button" className="file-picker-btn" onClick={handlePickDest}>
                    Browse
                  </button>
                </div>
                <div className="field-helper">
                  {sourceFiles.length > 1 
                    ? "Specify the folder where the output files will be saved."
                    : "Specify the path where the processed output file will be saved."}
                </div>
              </div>
            )}

            {(fileAction === "encrypt" || fileAction === "decrypt") && (
              activeMode === "password" ? (
                <div className="form-row">
                  <div className="form-group" style={{ flex: 2 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Password</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Password Mode:</strong>
                          Secures the container using a single master password. Strong key derivation (Argon2id or PBKDF2) is applied to protect against brute-force attacks.
                          <ul>
                            <li>Uses AES-256-GCM symmetric encryption.</li>
                            <li>Uses Argon2id or PBKDF2 for key derivation.</li>
                            <li><strong>Warning:</strong> If you lose the password, your data is lost forever. There is no recovery mechanism.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <input
                      type="password"
                      className="text-input"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter wrap password..."
                    />
                    <div className="field-helper">Enter the master key password. Lost passwords are unrecoverable.</div>
                  </div>
                  {fileAction === "encrypt" && (
                    <div className="form-group" style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                        <label style={{ marginBottom: 0 }}>KDF</label>
                        <div className="info-tooltip-wrapper">
                          <span className="info-icon">i</span>
                          <div className="tooltip-content">
                            <strong>Key Derivation Function:</strong>
                            Algorithm to derive the encryption key from the password.
                            <ul>
                              <li><strong>Argon2id:</strong> Memory-hard, GPU-resistant, state-of-the-art KDF (Highly Recommended).</li>
                              <li><strong>PBKDF2:</strong> Legacy standard, less resistant to GPU brute-forcing.</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                      <select
                        className="select-input"
                        value={kdfChoice}
                        onChange={(e) => setKdfChoice(e.target.value)}
                      >
                        <option value="Argon2id">Argon2id</option>
                        <option value="PBKDF2">PBKDF2</option>
                      </select>
                      <div className="field-helper">Argon2id is highly GPU-resistant (recommended).</div>
                    </div>
                  )}
                </div>
              ) : activeMode === "recipient" ? (
                <div className="form-group">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <label style={{ marginBottom: 0 }}>
                        {fileAction === "encrypt" ? "Recipient Public Key" : "Your Secret Key"}
                      </label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          {fileAction === "encrypt" ? (
                            <>
                              <strong>Hybrid KEM Mode:</strong>
                              Utilizes post-quantum hybrid public-key cryptography (ML-KEM-768 + X25519) to seal the container for a specific recipient keypair.
                              <ul>
                                <li>Combines post-quantum <strong>ML-KEM-768</strong> with classical <strong>X25519</strong>.</li>
                                <li>You need the recipient's <strong>Public Key</strong> (192-char hex) to encrypt.</li>
                                <li>Only the recipient's secret key can decrypt this container.</li>
                              </ul>
                            </>
                          ) : (
                            <>
                              <strong>Hybrid KEM Decryption:</strong>
                              Decrypts the container sealed for your keypair.
                              <ul>
                                <li>Paste your 192-character hexadecimal <strong>Secret Key</strong>.</li>
                                <li>Keep this key completely secure. If anyone gets this key, they can decrypt all containers sealed for you.</li>
                              </ul>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <button type="button" className="btn-secondary" onClick={loadKeyFromFile}>
                      Load File
                    </button>
                  </div>
                  <input
                    type="text"
                    className="text-input"
                    value={recipientKey}
                    onChange={(e) => setRecipientKey(e.target.value)}
                    placeholder={fileAction === "encrypt" ? "Paste public key hex..." : "Paste secret key hex..."}
                  />
                  <div className="field-helper">
                    {fileAction === "encrypt" 
                      ? "Paste the recipient's post-quantum public key (X25519 + ML-KEM) to encrypt for them."
                      : "Paste your private secret key (X25519 + ML-KEM) to decrypt the container."}
                  </div>
                </div>
              ) : (
                fileAction === "encrypt" ? (
                  <div className="form-row">
                    <div className="form-group">
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                        <label style={{ marginBottom: 0 }}>Threshold (t)</label>
                        <div className="info-tooltip-wrapper">
                          <span className="info-icon">i</span>
                          <div className="tooltip-content">
                            <strong>Threshold Mode (t-of-n):</strong>
                            Splits the access key into multiple independent SSS shares. The container can only be decrypted when at least 't' of the 'n' total shares are presented.
                            <ul>
                              <li><strong>Threshold (t):</strong> Minimum number of shares required to reconstruct the decryption key.</li>
                              <li>Must be at least 2, and less than or equal to total shares (n).</li>
                              <li>For example, in a 2-of-3 setup, any 2 shares can decrypt, but 1 share alone is completely useless.</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                      <input
                        type="number"
                        className="text-input"
                        value={thresholdT}
                        min={2}
                        max={thresholdN}
                        onChange={(e) => setThresholdT(parseInt(e.target.value) || 2)}
                        placeholder="Required shares (t)"
                      />
                      <div className="field-helper">Minimum number of shares (threshold) required to reconstruct the key.</div>
                    </div>
                    <div className="form-group">
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                        <label style={{ marginBottom: 0 }}>Total Shares (n)</label>
                        <div className="info-tooltip-wrapper">
                          <span className="info-icon">i</span>
                          <div className="tooltip-content">
                            <strong>Total Shares (n):</strong>
                            The total number of independent shares to generate.
                            <ul>
                              <li>Each generated share contains a piece of the secret key.</li>
                              <li>Distribute these shares to different custodians or secure locations.</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                      <input
                        type="number"
                        className="text-input"
                        value={thresholdN}
                        min={thresholdT}
                        max={255}
                        onChange={(e) => setThresholdN(parseInt(e.target.value) || 3)}
                        placeholder="Total shares to generate (n)"
                      />
                      <div className="field-helper">Total number of SSS shares to generate and distribute.</div>
                    </div>
                  </div>
                ) : (
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Pasted Shares & QR Codes</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Threshold Decryption:</strong>
                          Provide the generated shares to reconstruct the key.
                          <ul>
                            <li>Paste the share strings one by one, each on a new line.</li>
                            <li>Or drop/upload a share QR Code image to scan it automatically.</li>
                            <li>Each share must start with the <code>vcs_</code> prefix.</li>
                            <li>At least <strong>{thresholdT}</strong> valid shares must be provided to decrypt.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <div className="shares-grid">
                      <div>
                        <textarea
                          className="text-input"
                          value={inputShares}
                          onChange={(e) => setInputShares(e.target.value)}
                          placeholder="Paste shares here (one per line, e.g. vcs_...)"
                          style={{ minHeight: "120px", height: "100%" }}
                        />
                      </div>
                      <label
                        htmlFor="qr-file-input-file"
                        className={`qr-dropzone ${isQrDragOver ? "dragover" : ""}`}
                        onDragOver={handleQrDragOver}
                        onDragLeave={handleQrDragLeave}
                        onDrop={handleQrDrop}
                      >
                        <input
                          type="file"
                          id="qr-file-input-file"
                          accept="image/*"
                          onChange={handleQrUpload}
                          style={{ display: "none" }}
                          multiple
                        />
                        <svg className="qr-dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="3" width="7" height="7" />
                          <rect x="14" y="3" width="7" height="7" />
                          <rect x="14" y="14" width="7" height="7" />
                          <rect x="3" y="14" width="7" height="7" />
                          <rect x="7" y="7" width="2" height="2" fill="currentColor" />
                          <rect x="15" y="7" width="2" height="2" fill="currentColor" />
                          <rect x="7" y="15" width="2" height="2" fill="currentColor" />
                          <rect x="15" y="15" width="2" height="2" fill="currentColor" />
                        </svg>
                        <p className="qr-dropzone-text">Drop SSS QR image here or click to upload</p>
                        <span className="qr-dropzone-subtext">Scans and appends SSS share offline</span>
                      </label>
                    </div>
                    <div className="field-helper">Paste SSS share strings here or upload share QR Codes. At least {thresholdT || "t"} valid shares are required.</div>
                  </div>
                )
              )
            )}

            {(fileAction === "decrypt" || fileAction === "verify") && (
              <div className="verify-settings" style={{ borderTop: "1px solid #1f1f23", paddingTop: "14px", marginTop: "14px" }}>
                <h4 style={{ fontSize: "11px", fontWeight: "600", color: "#e4e4e7", marginBottom: "12px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  Shield Policy Configurations
                </h4>
                
                <div className="form-row">
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Release Mode</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Release Mode:</strong>
                          Determines how decrypted data is written to the destination file.
                          <ul>
                            <li><strong>Verified:</strong> Decrypts and verifies the full cryptographic signature before writing any data to disk (Highly Recommended).</li>
                            <li><strong>Streaming:</strong> Writes decrypted data to disk in real-time. Faster and memory-efficient for extremely large files, but may leave partial, unverified files if verification fails.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <select
                      className="select-input"
                      value={verifyReleaseMode}
                      onChange={(e) => setVerifyReleaseMode(e.target.value)}
                    >
                      <option value="verified">Verified (Double-pass, strict)</option>
                      <option value="streaming">Streaming (Fast, on-the-fly)</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Signature Policy</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Signature Policy:</strong>
                          Specifies how container signature checks are treated.
                          <ul>
                            <li><strong>Required (v2/v3):</strong> Strict compliance mode. The container must have a valid cryptographic signature log matching v2 (Ed25519) or v3 (Post-Quantum) formats. Decryption will abort if signature is missing.</li>
                            <li><strong>Optional (v1 fallback):</strong> Allows fallback decryption of legacy v1 containers that do not possess signature headers.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <select
                      className="select-input"
                      value={verifySignaturePolicy}
                      onChange={(e) => setVerifySignaturePolicy(e.target.value)}
                    >
                      <option value="required">Required (v2/v3 check)</option>
                      <option value="optional">Optional (v1 fallback)</option>
                    </select>
                  </div>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Rollback Pin Epoch</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Rollback Pin Epoch:</strong>
                          Prevents downgrading the container to older, vulnerable configurations.
                          <ul>
                            <li>Specify a minimum epoch version number.</li>
                            <li>Decryption will abort if the container header epoch is lower than this value.</li>
                            <li>Leave blank to disable rollback protection.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <input
                      type="number"
                      className="text-input"
                      value={verifyRollbackPin}
                      onChange={(e) => setVerifyRollbackPin(e.target.value)}
                      placeholder="e.g. 1 (optional)"
                    />
                  </div>
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>On Tamper Reaction</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>On Tamper Reaction:</strong>
                          Specifies how the decrypter responds if container tampering or signature mismatch is detected.
                          <ul>
                            <li><strong>Abort immediately:</strong> Instantly terminates the decryption process and deletes incomplete output (Recommended).</li>
                            <li><strong>Abort & report:</strong> Aborts and logs a detailed cryptographic audit report for analysis.</li>
                            <li><strong>Attempt recovery:</strong> Attempts to reconstruct and decrypt non-tampered data blocks. Use only for forensic analysis.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <select
                      className="select-input"
                      value={verifyOnTamper}
                      onChange={(e) => setVerifyOnTamper(e.target.value)}
                    >
                      <option value="abort">Abort immediately</option>
                      <option value="report">Abort & report</option>
                      <option value="recover">Attempt recovery</option>
                    </select>
                  </div>
                </div>

                <div className="form-group" style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "6px" }}>
                  <input
                    type="checkbox"
                    id="verifyFounderAnchor"
                    checked={verifyFounderAnchor}
                    onChange={(e) => setVerifyFounderAnchor(e.target.checked)}
                    style={{ accentColor: "#f97316" }}
                  />
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <label htmlFor="verifyFounderAnchor" style={{ marginBottom: 0, textTransform: "none", cursor: "pointer" }}>
                      Enforce Founder Anchor check
                    </label>
                    <div className="info-tooltip-wrapper">
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Founder Anchor Check:</strong>
                        Strict ownership verification policy.
                        <ul>
                          <li>Verifies the container's author/creator public key against the system's trusted anchor keys.</li>
                          <li>Prevents processing unauthorized or untrusted containers on this device.</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {fileAction === "seal" && (
              <div className="seal-settings" style={{ borderTop: "1px solid #1f1f23", paddingTop: "14px", marginTop: "14px" }}>
                <div style={{ backgroundColor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.25)", borderRadius: "6px", padding: "12px", marginBottom: "14px" }}>
                  <h4 style={{ fontSize: "11px", fontWeight: "700", color: "#f87171", marginBottom: "6px", textTransform: "uppercase" }}>
                    CRITICAL WARNING: IRREVERSIBLE OPERATION
                  </h4>
                  <p style={{ fontSize: "10px", color: "#fca5a5", lineHeight: "1.4" }}>
                    Sealing permanently purges the container's wraps, making recovery of the Data Encryption Key (DEK) mathematically impossible.
                  </p>
                  <p style={{ fontSize: "9px", color: "#fca5a5", opacity: 0.8, lineHeight: "1.4", marginTop: "6px" }}>
                    Note: Sealing cannot affect pre-existing cloud synchronization versions (e.g., Dropbox, OneDrive, iCloud previous commits) or backups stored elsewhere.
                  </p>
                </div>

                <div className="form-row">
                  <div className="form-group" style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Seal Mode</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Seal Mode:</strong>
                          Determines the action taken on the container.
                          <ul>
                            <li><strong>Seal:</strong> Purges the key wraps, making it mathematically impossible to decrypt, but leaves the encrypted ciphertext body in the file.</li>
                            <li><strong>Purge:</strong> Completely overwrites (crypto-shreds) the ciphertext body in addition to destroying the wrapping keys, ensuring total data erasure.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <select
                      className="select-input"
                      value={sealMode}
                      onChange={(e) => setSealMode(e.target.value)}
                    >
                      <option value="seal">Seal (Keep Ciphertext)</option>
                      <option value="purge">Purge (Crypto-Shred Ciphertext)</option>
                    </select>
                  </div>
                  <div className="form-group" style={{ flex: 2 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Reason / Audit Label</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Reason / Audit Label:</strong>
                          A permanent reason written directly into the sealed container marker. Helps audit the justification for sealing/purging (e.g. GDPR erasure request).
                        </div>
                      </div>
                    </div>
                    <input
                      type="text"
                      className="text-input"
                      value={sealReason}
                      onChange={(e) => setSealReason(e.target.value)}
                      placeholder="e.g. GDPR erasure request..."
                    />
                  </div>
                </div>

                <div className="form-group" style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                  <input
                    type="checkbox"
                    id="sealSignEnabled"
                    checked={sealSignEnabled}
                    onChange={(e) => setSealSignEnabled(e.target.checked)}
                    style={{ accentColor: "#f97316" }}
                  />
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <label htmlFor="sealSignEnabled" style={{ marginBottom: 0, textTransform: "none", cursor: "pointer" }}>
                      Sign Sealed Marker (Recommended for v2/v3)
                    </label>
                    <div className="info-tooltip-wrapper">
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Sign Sealed Marker:</strong>
                        Cryptographically signs the sealed container state using a signing key. Prevents unauthorized tampering with the sealed header block.
                      </div>
                    </div>
                  </div>
                </div>

                {sealSignEnabled && (
                  <div style={{ backgroundColor: "#141416", border: "1px solid #1f1f23", borderRadius: "6px", padding: "10px", marginBottom: "14px" }}>
                    <div className="form-row">
                      <div className="form-group" style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                          <label style={{ marginBottom: 0 }}>Signer Type</label>
                          <div className="info-tooltip-wrapper">
                            <span className="info-icon">i</span>
                            <div className="tooltip-content">
                              <strong>Signer Type:</strong>
                              Selects the signature algorithm.
                              <ul>
                                <li><strong>Ed25519:</strong> Fast, classical elliptic curve signatures (v2 standard).</li>
                                <li><strong>Post-Quantum:</strong> Uses quantum-resistant hybrid signature schemes (v3 standard).</li>
                              </ul>
                            </div>
                          </div>
                        </div>
                        <select
                          className="select-input"
                          value={sealSignKind}
                          onChange={(e) => setSealSignKind(e.target.value)}
                        >
                          <option value="plain">Ed25519 (v2)</option>
                          <option value="hybrid">Post-Quantum (v3)</option>
                        </select>
                      </div>
                      <div className="form-group" style={{ flex: 2 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                          <label style={{ marginBottom: 0 }}>Key Log ID (Hex)</label>
                          <div className="info-tooltip-wrapper">
                            <span className="info-icon">i</span>
                            <div className="tooltip-content">
                              <strong>Key Log ID:</strong>
                              A 32-byte hexadecimal identifier of the public key to associate with this seal signature.
                            </div>
                          </div>
                        </div>
                        <input
                          type="text"
                          className="text-input"
                          value={sealKeyLogId}
                          onChange={(e) => setSealKeyLogId(e.target.value)}
                          placeholder="32-byte hex ID..."
                        />
                      </div>
                    </div>
                    <div className="form-group">
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                        <label style={{ marginBottom: 0 }}>Signer Public Key (Hex)</label>
                        <div className="info-tooltip-wrapper">
                          <span className="info-icon">i</span>
                          <div className="tooltip-content">
                            <strong>Signer Public Key:</strong>
                            The public key of the authority sealing the container.
                          </div>
                        </div>
                      </div>
                      <input
                        type="text"
                        className="text-input"
                        value={sealSignerPk}
                        onChange={(e) => setSealSignerPk(e.target.value)}
                        placeholder="Paste public key hex..."
                      />
                    </div>
                    <div className="form-group">
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                        <label style={{ marginBottom: 0 }}>Signer Secret Key (Hex)</label>
                        <div className="info-tooltip-wrapper">
                          <span className="info-icon">i</span>
                          <div className="tooltip-content">
                            <strong>Signer Secret Key:</strong>
                            The private secret key required to generate the cryptographic signature for the seal.
                          </div>
                        </div>
                      </div>
                      <input
                        type="password"
                        className="text-input"
                        value={sealSignerSk}
                        onChange={(e) => setSealSignerSk(e.target.value)}
                        placeholder="Paste secret key hex..."
                      />
                    </div>
                  </div>
                )}

                <div className="form-group">
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                    <label style={{ marginBottom: 0, color: "#f87171" }}>Type "SEAL" to confirm</label>
                    <div className="info-tooltip-wrapper">
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Confirmation:</strong>
                        Ensures you deliberately intend to perform this irreversible action. If confirmed, recovery of the data will be impossible.
                      </div>
                    </div>
                  </div>
                  <input
                    type="text"
                    className="text-input"
                    value={sealConfirmText}
                    onChange={(e) => setSealConfirmText(e.target.value)}
                    placeholder="Type SEAL..."
                    style={{ borderColor: sealConfirmText === "SEAL" ? "#ef4444" : "#1f1f23" }}
                  />
                </div>
              </div>
            )}

            <div style={{ marginTop: "24px" }}>
              <button
                type="submit"
                className="btn-primary"
                disabled={loading || (fileAction === "seal" && sealConfirmText !== "SEAL")}
                style={{
                  backgroundColor: fileAction === "seal" ? "#ef4444" : "#f97316",
                }}
              >
                {fileAction === "encrypt"
                  ? "Encrypt File"
                  : fileAction === "decrypt"
                  ? "Decrypt File"
                  : fileAction === "verify"
                  ? "Verify Container"
                  : "Seal Container"}
              </button>
            </div>

            {/* Progress Display */}
            {fileProgress && (
              <div
                className="progress-panel"
                style={{
                  marginTop: "20px",
                  padding: "14px",
                  backgroundColor: "#16161a",
                  borderRadius: "8px",
                  border: "1px solid #232329",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "8px",
                    fontSize: "12px",
                    color: "#e4e4e7",
                    fontWeight: "500",
                  }}
                >
                  <span
                    style={{
                      textOverflow: "ellipsis",
                      overflow: "hidden",
                      whiteSpace: "nowrap",
                      maxWidth: "280px",
                    }}
                    title={fileProgress.filePath}
                  >
                    {getFilename(fileProgress.filePath)}
                  </span>
                  <span style={{ color: "#f97316", fontWeight: "600" }}>
                    {fileProgress.percentage}%
                  </span>
                </div>
                
                <div
                  style={{
                    height: "6px",
                    backgroundColor: "#27272a",
                    borderRadius: "3px",
                    overflow: "hidden",
                    marginBottom: "10px",
                  }}
                >
                  <div
                    style={{
                      width: `${fileProgress.percentage}%`,
                      height: "100%",
                      backgroundColor: "#f97316",
                      borderRadius: "3px",
                      transition: "width 0.1s ease-out",
                    }}
                  />
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    fontSize: "11px",
                    color: "#a1a1aa",
                  }}
                >
                  <span>
                    {formatBytes(fileProgress.bytesProcessed)} / {formatBytes(fileProgress.totalBytes)}
                  </span>
                  {fileProgress.eta !== null && (
                    <span style={{ color: "#f97316" }}>
                      Remaining: {formatTime(fileProgress.eta)}
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Generated Shares Display */}
            {fileAction === "encrypt" && activeMode === "threshold" && generatedShares && generatedShares.length > 0 && (
              <div className="display-box-container">
                <div className="display-box-header">
                  <span className="display-box-title">Generated Secret Shares ({thresholdT} of {thresholdN})</span>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => copyToClipboard(generatedShares.join("\n"), "All SSS shares")}
                  >
                    Copy All
                  </button>
                </div>
                <div className="display-box" style={{ maxHeight: "200px" }}>
                  {generatedShares.map((share, idx) => (
                    <div key={idx} style={{ marginBottom: "8px", borderBottom: idx < generatedShares.length - 1 ? "1px solid #1f1f23" : "none", paddingBottom: "6px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontSize: "10px", color: "#f97316", fontWeight: "600" }}>Share #{idx + 1}</span>
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: "8px", padding: "2px 6px" }}
                            onClick={() => handleShowQr(share, `Share #${idx + 1}`)}
                          >
                            View QR
                          </button>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: "8px", padding: "2px 6px" }}
                            onClick={() => copyToClipboard(share, `Share #${idx + 1}`)}
                          >
                            Copy Share
                          </button>
                        </div>
                      </div>
                      <div style={{ fontFamily: "monospace", fontSize: "10px", color: "#e4e4e7", wordBreak: "break-all" }}>
                        {share}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Verify Report Display */}
            {fileAction === "verify" && verifyReport && (
              <div className="display-box-container">
                <div className="display-box-header">
                  <span className="display-box-title">Shield Integrity Verification Report</span>
                  <span className={`status-badge ${verifyReport === "Success" ? "success" : verifyReport === "ContainerSealed" ? "warning" : "error"}`} style={{
                    fontSize: "9px",
                    fontWeight: "700",
                    padding: "2px 6px",
                    borderRadius: "4px",
                    textTransform: "uppercase",
                    backgroundColor: verifyReport === "Success" ? "rgba(34, 197, 94, 0.15)" : verifyReport === "ContainerSealed" ? "rgba(245, 158, 11, 0.15)" : "rgba(239, 68, 68, 0.15)",
                    color: verifyReport === "Success" ? "#4ade80" : verifyReport === "ContainerSealed" ? "#fbbf24" : "#f87171",
                    border: verifyReport === "Success" ? "1px solid rgba(34, 197, 94, 0.25)" : verifyReport === "ContainerSealed" ? "1px solid rgba(245, 158, 11, 0.25)" : "1px solid rgba(239, 68, 68, 0.25)"
                  }}>
                    {verifyReport}
                  </span>
                </div>
                <div className="display-box" style={{ maxHeight: "150px" }}>
                  {verifyReport === "Success" ? (
                    "✓ Container integrity verified. All cryptographic checks, chunk indexes, tag chains, and signatures are intact and valid."
                  ) : verifyReport === "ContainerSealed" ? (
                    "⚠ Container has been sovereignly sealed. Standard decryption is blocked. Sealed metadata is displayed below."
                  ) : (
                    `❌ Integrity check failed: ${verifyReport}. Do not attempt decryption as the container appears to be tampered with or corrupted.`
                  )}
                </div>

                {/* Inspect sealed container if available */}
                {sealedInspection && (
                  <div className="sealed-details" style={{ marginTop: "12px", borderTop: "1px dashed #1f1f23", paddingTop: "12px" }}>
                    <h5 style={{ fontSize: "10px", fontWeight: "600", color: "#fbbf24", marginBottom: "8px", textTransform: "uppercase" }}>
                      Sealed Container Inspection
                    </h5>
                    <table style={{ width: "100%", fontSize: "11px", color: "#a1a1aa", borderCollapse: "collapse" }}>
                      <tbody>
                        <tr>
                          <td style={{ padding: "3px 0", fontWeight: "500" }}>Version</td>
                          <td style={{ padding: "3px 0", textAlign: "right", fontFamily: "monospace" }}>{sealedInspection.version}</td>
                        </tr>
                        <tr>
                          <td style={{ padding: "3px 0", fontWeight: "500" }}>File ID</td>
                          <td style={{ padding: "3px 0", textAlign: "right", fontFamily: "monospace", fontSize: "9px" }}>{sealedInspection.fileId}</td>
                        </tr>
                        <tr>
                          <td style={{ padding: "3px 0", fontWeight: "500" }}>Plaintext Size</td>
                          <td style={{ padding: "3px 0", textAlign: "right" }}>{sealedInspection.plaintextSize} bytes</td>
                        </tr>
                        <tr>
                          <td style={{ padding: "3px 0", fontWeight: "500" }}>Sealed Mode</td>
                          <td style={{ padding: "3px 0", textAlign: "right" }}>
                            <span style={{
                              fontWeight: "600",
                              color: sealedInspection.sealedMode === 1 ? "#ef4444" : "#fbbf24"
                            }}>
                              {sealedInspection.sealedMode === 1 ? "PURGE (Shredded)" : "SEAL (Keyless)"}
                            </span>
                          </td>
                        </tr>
                        {sealedInspection.reason && (
                          <tr>
                            <td style={{ padding: "3px 0", fontWeight: "500" }}>Reason</td>
                            <td style={{ padding: "3px 0", textAlign: "right", fontStyle: "italic" }}>"{sealedInspection.reason}"</td>
                          </tr>
                        )}
                        {sealedInspection.timestamp > 0 && (
                          <tr>
                            <td style={{ padding: "3px 0", fontWeight: "500" }}>Sealed At</td>
                            <td style={{ padding: "3px 0", textAlign: "right" }}>{new Date(sealedInspection.timestamp * 1000).toLocaleString()}</td>
                          </tr>
                        )}
                        <tr>
                          <td style={{ padding: "3px 0", fontWeight: "500" }}>Ciphertext Body</td>
                          <td style={{ padding: "3px 0", textAlign: "right" }}>
                            {sealedInspection.ciphertextPresent ? "Present (Encrypted)" : "Absent (Purged/Deleted)"}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </form>
        )}

        {/* Text Tab */}
        {activeTab === "text" && (
          <form onSubmit={handleTextProcess}>
            <div className="settings-row">
              <div className="segmented-control">
                <button
                  type="button"
                  className={`segment-btn ${textAction === "encrypt" ? "active" : ""}`}
                  onClick={() => {
                    setTextAction("encrypt");
                    setInputText("");
                    setOutputText("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                  }}
                >
                  Encrypt
                </button>
                <button
                  type="button"
                  className={`segment-btn ${textAction === "decrypt" ? "active" : ""}`}
                  onClick={() => {
                    setTextAction("decrypt");
                    setInputText("");
                    setOutputText("");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setThresholdT(2);
                    setThresholdN(3);
                    setStatus(null);
                  }}
                >
                  Decrypt
                </button>
              </div>

              <div className="segmented-control" style={{ display: "flex", width: "100%" }}>
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "password" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setActiveMode("password");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setStatus(null);
                  }}
                >
                  Password
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Password Mode:</strong>
                      Secures the container using a master password with Argon2id or PBKDF2 key derivation.
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "recipient" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setActiveMode("recipient");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setStatus(null);
                  }}
                >
                  Hybrid KEM
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Hybrid KEM Mode:</strong>
                      Utilizes post-quantum ML-KEM-768 combined with classical X25519 public-key cryptography to seal for a specific recipient keypair.
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "threshold" ? "active" : ""}`}
                  style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}
                  onClick={() => {
                    setActiveMode("threshold");
                    setPassword("");
                    setRecipientKey("");
                    setInputShares("");
                    setGeneratedShares(null);
                    setStatus(null);
                  }}
                >
                  Threshold (t-of-n)
                  <div className="info-tooltip-wrapper" style={{ marginLeft: "6px" }}>
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      <strong>Threshold Mode:</strong>
                      Splits the access key into multiple independent SSS shares, requiring at least 't' shares to decrypt.
                    </div>
                  </div>
                </button>
              </div>
            </div>


            <div className="form-group">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <label style={{ marginBottom: 0 }}>{textAction === "encrypt" ? "Plaintext Message" : "Hex Container Ciphertext"}</label>
                {textAction === "decrypt" && (
                  <button type="button" className="btn-secondary" onClick={loadBinFromFile}>
                    Load File
                  </button>
                )}
              </div>
              <textarea
                className="text-input"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={textAction === "encrypt" ? "Enter your secret message here..." : "Paste encrypted hex container or load file..."}
              />
              <div className="field-helper">
                {textAction === "encrypt"
                  ? "Type or paste the secret message you want to encrypt."
                  : "Paste the hexadecimal ciphertext container string to decrypt."}
              </div>
            </div>

            {activeMode === "password" ? (
              <div className="form-row">
                <div className="form-group" style={{ flex: 2 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                    <label style={{ marginBottom: 0 }}>Password</label>
                    <div className="info-tooltip-wrapper">
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Password Mode:</strong>
                        Encrypts or decrypts text messages using a single password string with robust key derivation.
                        <ul>
                          <li>Uses AES-256-GCM symmetric encryption.</li>
                          <li>Uses Argon2id or PBKDF2 for key derivation.</li>
                          <li><strong>Warning:</strong> If you lose the password, your data is lost forever. There is no recovery mechanism.</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  <input
                    type="password"
                    className="text-input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter wrap password..."
                  />
                  <div className="field-helper">Enter the master key password. Lost passwords cannot be reset or recovered.</div>
                </div>
                {textAction === "encrypt" && (
                  <div className="form-group" style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>KDF</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Key Derivation Function:</strong>
                          Algorithm to derive the encryption key from the password.
                          <ul>
                            <li><strong>Argon2id:</strong> Memory-hard, GPU-resistant, state-of-the-art KDF (Highly Recommended).</li>
                            <li><strong>PBKDF2:</strong> Legacy standard, less resistant to GPU brute-forcing.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <select
                      className="select-input"
                      value={kdfChoice}
                      onChange={(e) => setKdfChoice(e.target.value)}
                    >
                      <option value="Argon2id">Argon2id</option>
                      <option value="PBKDF2">PBKDF2</option>
                    </select>
                    <div className="field-helper">Argon2id is highly GPU-resistant (recommended).</div>
                  </div>
                )}
              </div>
            ) : activeMode === "recipient" ? (
              <div className="form-group">
                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                  <label style={{ marginBottom: 0 }}>
                    {textAction === "encrypt" ? "Recipient Public Key" : "Your Secret Key"}
                  </label>
                  <div className="info-tooltip-wrapper">
                    <span className="info-icon">i</span>
                    <div className="tooltip-content">
                      {textAction === "encrypt" ? (
                        <>
                          <strong>Hybrid KEM Mode:</strong>
                          Secures text using a public key for a designated recipient. Only their matching secret key can decrypt it.
                          <ul>
                            <li>Combines post-quantum <strong>ML-KEM-768</strong> with classical <strong>X25519</strong>.</li>
                            <li>You need the recipient's <strong>Public Key</strong> (192-char hex) to encrypt.</li>
                            <li>Only the recipient's secret key can decrypt this container.</li>
                          </ul>
                        </>
                      ) : (
                        <>
                          <strong>Hybrid KEM Decryption:</strong>
                          Decrypts the container sealed for your keypair.
                          <ul>
                            <li>Paste your 192-character hexadecimal <strong>Secret Key</strong>.</li>
                            <li>Keep this key completely secure. If anyone gets this key, they can decrypt all containers sealed for you.</li>
                          </ul>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <input
                  type="text"
                  className="text-input"
                  value={recipientKey}
                  onChange={(e) => setRecipientKey(e.target.value)}
                  placeholder="Paste hexadecimal key..."
                />
                <div className="field-helper">
                  {textAction === "encrypt"
                    ? "Paste the recipient's post-quantum public key (X25519 + ML-KEM) to encrypt for them."
                    : "Paste your private secret key (X25519 + ML-KEM) to decrypt this container."}
                </div>
              </div>
            ) : (
              textAction === "encrypt" ? (
                <div className="form-row">
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Threshold (t)</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Threshold Mode (t-of-n):</strong>
                          Encrypts text using Shamir Secret Sharing. Generates copyable shares that must be recombined to decrypt.
                          <ul>
                            <li><strong>Threshold (t):</strong> Minimum number of shares required to reconstruct the decryption key.</li>
                            <li>Must be at least 2, and less than or equal to total shares (n).</li>
                            <li>For example, in a 2-of-3 setup, any 2 shares can decrypt, but 1 share alone is completely useless.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <input
                      type="number"
                      className="text-input"
                      value={thresholdT}
                      min={2}
                      max={thresholdN}
                      onChange={(e) => setThresholdT(parseInt(e.target.value) || 2)}
                      placeholder="Required shares (t)"
                    />
                    <div className="field-helper">Minimum number of shares required to decrypt.</div>
                  </div>
                  <div className="form-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                      <label style={{ marginBottom: 0 }}>Total Shares (n)</label>
                      <div className="info-tooltip-wrapper">
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Total Shares (n):</strong>
                          The total number of independent shares to generate.
                          <ul>
                            <li>Each generated share contains a piece of the secret key.</li>
                            <li>Distribute these shares to different custodians or secure locations.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                    <input
                      type="number"
                      className="text-input"
                      value={thresholdN}
                      min={thresholdT}
                      max={255}
                      onChange={(e) => setThresholdN(parseInt(e.target.value) || 3)}
                      placeholder="Total shares to generate (n)"
                    />
                    <div className="field-helper">Total number of SSS shares to generate.</div>
                  </div>
                </div>
              ) : (
                <div className="form-group">
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                    <label style={{ marginBottom: 0 }}>Pasted Shares & QR Codes</label>
                    <div className="info-tooltip-wrapper">
                      <span className="info-icon">i</span>
                      <div className="tooltip-content">
                        <strong>Threshold Decryption:</strong>
                        Provide the generated shares to reconstruct the key.
                        <ul>
                          <li>Paste the share strings one by one, each on a new line.</li>
                          <li>Or drop/upload a share QR Code image to scan it automatically.</li>
                          <li>Each share must start with the <code>vcs_</code> prefix.</li>
                          <li>At least <strong>{thresholdT}</strong> valid shares must be provided to decrypt.</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  <div className="shares-grid">
                    <div>
                      <textarea
                        className="text-input"
                        value={inputShares}
                        onChange={(e) => setInputShares(e.target.value)}
                        placeholder="Paste shares here (one per line, e.g. vcs_...)"
                        style={{ minHeight: "120px", height: "100%" }}
                      />
                    </div>
                    <label
                      htmlFor="qr-file-input-text"
                      className={`qr-dropzone ${isQrDragOver ? "dragover" : ""}`}
                      onDragOver={handleQrDragOver}
                      onDragLeave={handleQrDragLeave}
                      onDrop={handleQrDrop}
                    >
                      <input
                        type="file"
                        id="qr-file-input-text"
                        accept="image/*"
                        onChange={handleQrUpload}
                        style={{ display: "none" }}
                        multiple
                      />
                      <svg className="qr-dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="3" width="7" height="7" />
                        <rect x="14" y="3" width="7" height="7" />
                        <rect x="14" y="14" width="7" height="7" />
                        <rect x="3" y="14" width="7" height="7" />
                        <rect x="7" y="7" width="2" height="2" fill="currentColor" />
                        <rect x="15" y="7" width="2" height="2" fill="currentColor" />
                        <rect x="7" y="15" width="2" height="2" fill="currentColor" />
                        <rect x="15" y="15" width="2" height="2" fill="currentColor" />
                      </svg>
                      <p className="qr-dropzone-text">Drop SSS QR image here or click to upload</p>
                      <span className="qr-dropzone-subtext">Scans and appends SSS share offline</span>
                    </label>
                  </div>
                  <div className="field-helper">Paste SSS share strings here or upload share QR Codes. At least {thresholdT || "t"} valid shares are required.</div>
                </div>
              )
            )}

            <div style={{ marginTop: "18px", marginBottom: "16px" }}>
              <button type="submit" className="btn-primary" disabled={loading}>
                {textAction === "encrypt" ? "Encrypt Text" : "Decrypt Text"}
              </button>
            </div>

            {outputText && (
              <div className="display-box-container">
                <div className="display-box-header">
                  <span className="display-box-title">{textAction === "encrypt" ? "Ciphertext Container (Hex)" : "Decrypted Text"}</span>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <button type="button" className="btn-secondary" onClick={() => copyToClipboard(outputText, "Output")}>
                      Copy
                    </button>
                    {textAction === "encrypt" && (
                      <button type="button" className="btn-secondary" onClick={() => saveBinToFile("Ciphertext", outputText, "encrypted_text.voll")}>
                        Save File
                      </button>
                    )}
                  </div>
                </div>
                <div className="display-box">{outputText}</div>
              </div>
            )}

            {/* Generated Shares Display for Text */}
            {textAction === "encrypt" && activeMode === "threshold" && generatedShares && generatedShares.length > 0 && (
              <div className="display-box-container">
                <div className="display-box-header">
                  <span className="display-box-title">Generated Secret Shares ({thresholdT} of {thresholdN})</span>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => copyToClipboard(generatedShares.join("\n"), "All SSS shares")}
                  >
                    Copy All
                  </button>
                </div>
                <div className="display-box" style={{ maxHeight: "200px" }}>
                  {generatedShares.map((share, idx) => (
                    <div key={idx} style={{ marginBottom: "8px", borderBottom: idx < generatedShares.length - 1 ? "1px solid #1f1f23" : "none", paddingBottom: "6px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontSize: "10px", color: "#f97316", fontWeight: "600" }}>Share #{idx + 1}</span>
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: "8px", padding: "2px 6px" }}
                            onClick={() => handleShowQr(share, `Share #${idx + 1}`)}
                          >
                            View QR
                          </button>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: "8px", padding: "2px 6px" }}
                            onClick={() => copyToClipboard(share, `Share #${idx + 1}`)}
                          >
                            Copy Share
                          </button>
                        </div>
                      </div>
                      <div style={{ fontFamily: "monospace", fontSize: "10px", color: "#e4e4e7", wordBreak: "break-all" }}>
                        {share}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </form>
        )}

        {/* Keys Tab */}
        {activeTab === "key" && (
          <div>
            <div className="form-group">
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
                <span style={{ fontSize: "11px", fontWeight: "600", color: "#e4e4e7", textTransform: "uppercase", letterSpacing: "0.5px" }}>Keypair Manager</span>
                <div className="info-tooltip-wrapper" style={{ margin: 0 }}>
                  <span className="info-icon">i</span>
                  <div className="tooltip-content">
                    <strong>Hybrid Keypair:</strong>
                    Generates a secure post-quantum cryptographic keypair consisting of a Public Key and a Secret Key.
                  </div>
                </div>
              </div>
              <button type="button" className="btn-primary" onClick={handleGenerateKeys} disabled={loading} style={{ margin: "0 0 16px" }}>
                Generate Hybrid Keypair
              </button>
              <p style={{ fontSize: "11px", color: "#52525b", lineHeight: "1.4" }}>
                Generates a quantum-resistant keypair combining **ML-KEM-768** post-quantum encapsulation with classical **X25519** ECDH.
              </p>
            </div>

            {generatedPk && (
              <div className="display-box-container">
                <div className="key-section">
                  <div className="display-box-header">
                    <span className="display-box-title" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      Public Key (Share openly)
                      <div className="info-tooltip-wrapper" style={{ margin: 0 }}>
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Public Key:</strong>
                          Your public identity key. Share this key openly with others so they can encrypt files specifically for you.
                        </div>
                      </div>
                    </span>
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button type="button" className="btn-secondary" onClick={() => copyToClipboard(generatedPk, "Public key")}>Copy</button>
                      <button type="button" className="btn-secondary" onClick={() => saveTextToFile("Public Key", generatedPk, "vollcrypt_public_key.pub")}>Save File</button>
                    </div>
                  </div>
                  <div className="display-box" style={{ maxHeight: "70px" }}>{generatedPk}</div>
                </div>

                <div className="key-section" style={{ marginTop: "16px" }}>
                  <div className="display-box-header">
                    <span className="display-box-title" style={{ color: "#f87171", display: "flex", alignItems: "center", gap: "6px" }}>
                      Secret Key (Keep secure!)
                      <div className="info-tooltip-wrapper" style={{ margin: 0 }}>
                        <span className="info-icon">i</span>
                        <div className="tooltip-content">
                          <strong>Secret Key:</strong>
                          Your private decryption key. Never share this key with anyone. It is used to decrypt files encrypted for you.
                        </div>
                      </div>
                    </span>
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button type="button" className="btn-secondary" onClick={() => copyToClipboard(generatedSk, "Secret key")}>Copy</button>
                      <button type="button" className="btn-secondary" onClick={() => saveTextToFile("Secret Key", generatedSk, "vollcrypt_secret_key.sec")}>Save File</button>
                    </div>
                  </div>
                  <div className="display-box" style={{ maxHeight: "70px" }}>{generatedSk}</div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Global Banner */}
        {status && (
          <div className={`status-msg ${status.type}`}>
            {status.msg === "ContainerSealed" ? (
              <div style={{ textAlign: "left" }}>
                <strong style={{ display: "block", marginBottom: "4px" }}>Access Denied: Container Sealed</strong>
                <span style={{ fontSize: "11px", opacity: 0.9 }}>
                  This container has been sovereignly sealed and cannot be decrypted. Access to the wrapping keys is permanently destroyed.
                </span>
              </div>
            ) : (
              status.msg
            )}
          </div>
        )}

        {/* Footer Info */}
        <footer className="gdpr-notice">
          Local cryptography execution. No data is sent over the network. GDPR & ISO 27001 compliant by design.
        </footer>

        {/* Settings Modal */}
        {showSettingsModal && (
          <div className="settings-modal-backdrop" onClick={() => setShowSettingsModal(false)}>
            <div className="settings-modal-card" onClick={(e) => e.stopPropagation()}>
              <div className="settings-modal-header">
                <h3>Application Settings</h3>
                <button type="button" className="settings-modal-close-btn" onClick={() => setShowSettingsModal(false)}>
                  ✕
                </button>
              </div>
              <div className="settings-modal-body">
                {/* Performance Section */}
                <div className="settings-section">
                  <span className="settings-section-title">Performance Profile</span>
                  <div className="settings-description">
                    Configure resource profiles for security derivation and processing:
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", marginBottom: 0, textTransform: "none", fontSize: "11px", color: "#e4e4e7", fontWeight: "bold" }}>
                        <input
                          type="radio"
                          name="perfProfile"
                          value="high"
                          checked={performanceProfile === "high"}
                          onChange={() => setPerformanceProfile("high")}
                          style={{ accentColor: "var(--accent-color)" }}
                        />
                        High Performance
                      </label>
                      <div style={{ paddingLeft: "20px", fontSize: "10px", color: "#a1a1aa" }}>
                        Maximizes speed using all processor cores. Best for encrypting large folders quickly.
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", marginBottom: 0, textTransform: "none", fontSize: "11px", color: "#e4e4e7", fontWeight: "bold" }}>
                        <input
                          type="radio"
                          name="perfProfile"
                          value="balanced"
                          checked={performanceProfile === "balanced"}
                          onChange={() => setPerformanceProfile("balanced")}
                          style={{ accentColor: "var(--accent-color)" }}
                        />
                        Balanced
                      </label>
                      <div style={{ paddingLeft: "20px", fontSize: "10px", color: "#a1a1aa" }}>
                        Uses moderate processor resources. Offers a stable balance between speed and system responsiveness.
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", marginBottom: 0, textTransform: "none", fontSize: "11px", color: "#e4e4e7", fontWeight: "bold" }}>
                        <input
                          type="radio"
                          name="perfProfile"
                          value="low"
                          checked={performanceProfile === "low"}
                          onChange={() => setPerformanceProfile("low")}
                          style={{ accentColor: "var(--accent-color)" }}
                        />
                        Low Resource
                      </label>
                      <div style={{ paddingLeft: "20px", fontSize: "10px", color: "#a1a1aa" }}>
                        Minimizes processor usage. Prevents background slowdowns on older or low-power devices.
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", marginBottom: 0, textTransform: "none", fontSize: "11px", color: "#e4e4e7", fontWeight: "bold" }}>
                        <input
                          type="radio"
                          name="perfProfile"
                          value="maximum"
                          checked={performanceProfile === "maximum"}
                          onChange={() => setPerformanceProfile("maximum")}
                          style={{ accentColor: "var(--accent-color)" }}
                        />
                        Paranoid (Maximum Security)
                      </label>
                      <div style={{ paddingLeft: "20px", fontSize: "10px", color: "#a1a1aa" }}>
                        Strengthens protection against password cracking using intensive security parameters. Processing may take longer.
                      </div>
                    </div>
                  </div>
                </div>

                {/* Clipboard Security Section */}
                <div className="settings-section">
                  <span className="settings-section-title">Clipboard Security</span>
                  <div className="settings-description">
                    Configure automatic clearing of copied keys or shares from the system clipboard:
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "4px" }}>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={clipboardClearEnabled}
                          onChange={(e) => setClipboardClearEnabled(e.target.checked)}
                        />
                        <span className="slider"></span>
                      </label>
                      <span style={{ fontSize: "11px", color: "#e4e4e7", userSelect: "none" }}>
                        Enable Auto-Clear for copied secrets
                      </span>
                    </div>
                    {clipboardClearEnabled && (
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                        <span style={{ fontSize: "11px", color: "#a1a1aa" }}>Clear after:</span>
                        <select
                          className="select-input"
                          value={clipboardClearDelay}
                          onChange={(e) => setClipboardClearDelay(Number(e.target.value))}
                          style={{ flex: 1, padding: "6px 8px", fontSize: "11px" }}
                        >
                          <option value={15}>15 Seconds</option>
                          <option value={30}>30 Seconds</option>
                          <option value={60}>60 Seconds (1 Minute)</option>
                          <option value={300}>300 Seconds (5 Minutes)</option>
                        </select>
                      </div>
                    )}
                  </div>
                </div>
              </div>
              <div className="settings-modal-footer">
                <button
                  type="button"
                  className="btn-primary"
                  style={{ width: "auto", padding: "8px 24px" }}
                  onClick={() => setShowSettingsModal(false)}
                >
                  Apply & Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* SSS QR Viewer Modal */}
        {activeQrSvg && (
          <div className="settings-modal-backdrop" onClick={() => { setActiveQrSvg(null); setActiveQrShare(null); setActiveQrTitle(null); }}>
            <div className="settings-modal-card" style={{ maxWidth: "320px", display: "flex", flexDirection: "column", alignItems: "center" }} onClick={(e) => e.stopPropagation()}>
              <div className="settings-modal-header" style={{ width: "100%" }}>
                <h3>{activeQrTitle} QR Code</h3>
                <button type="button" className="settings-modal-close-btn" onClick={() => { setActiveQrSvg(null); setActiveQrShare(null); setActiveQrTitle(null); }}>
                  ✕
                </button>
              </div>
              <div className="settings-modal-body" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "16px", padding: "20px 0" }}>
                <div 
                  style={{ 
                    background: "#ffffff", 
                    padding: "12px", 
                    borderRadius: "8px", 
                    boxShadow: "0 4px 12px rgba(0, 0, 0, 0.5)", 
                    display: "flex", 
                    justifyContent: "center", 
                    alignItems: "center" 
                  }}
                  dangerouslySetInnerHTML={{ __html: activeQrSvg }}
                />
                <div style={{ wordBreak: "break-all", fontSize: "9px", fontFamily: "monospace", color: "#a1a1aa", textAlign: "center", maxWidth: "260px" }}>
                  {activeQrShare}
                </div>
              </div>
              <div className="settings-modal-footer" style={{ width: "100%", justifyContent: "center", gap: "10px" }}>
                <button type="button" className="btn-primary" onClick={handleDownloadQr} style={{ fontSize: "11px", padding: "8px 16px" }}>
                  Download PNG
                </button>
                <button type="button" className="btn-secondary" onClick={() => { setActiveQrSvg(null); setActiveQrShare(null); setActiveQrTitle(null); }} style={{ fontSize: "11px", padding: "8px 16px" }}>
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  </div>
  );
}

export default App;

const EULA_TEXT = `END USER LICENSE AGREEMENT (EULA) AND PRIVACY POLICY
Software: Vollcrypt Desktop
Last Updated: June 2026

Compliance Frameworks: EU GDPR (2016/679), TR KVKK (No. 6698), US CCPA/CPRA

IMPORTANT – READ CAREFULLY: This End User License Agreement and Privacy Policy ("Agreement") is a legally binding contract between you (the "User") and the developer(s)/owner(s) of Vollcrypt Desktop ("Developer"). By installing, running, or using the Software, you acknowledge that you have read, understood, and agree to be bound by this Agreement. If you do not agree, do not install or use the Software.

1. GRANT OF LICENSE
Subject to your compliance with this Agreement, the Developer grants you a limited, non-exclusive, non-transferable, revocable license to install and use the Software on your local device solely for local data encryption and decryption. All intellectual property rights in the Software remain exclusively with the Developer.

2. PRIVACY POLICY & REGULATORY COMPLIANCE (GDPR, KVKK, CCPA)
The Software is engineered under the strict principles of Privacy by Design and Zero-Knowledge Architecture. Because the Software operates completely offline, the following compliance disclosures apply globally:

A. General Data Practices (All Jurisdictions)
- No Collection: The Software does not collect, store, log, monitor, or transmit any Personal Data, Personal Information, sensitive data, telemetry, or usage metrics.
- Local Processing Only: All cryptographic operations (encryption, decryption, key generation) are executed entirely on your local machine's CPU/RAM. No data ever leaves your device.
- No Access to Keys/Files: Your master passwords, encryption keys, and source files are never visible to, or accessible by, the Developer.

B. EU GDPR Compliance Statement
Pursuant to the General Data Protection Regulation (GDPR) (EU) 2016/679:
- Data Controller: Since the Developer does not collect or process any personal data via the Software, the Developer does not act as a "Data Controller" or "Data Processor" under the GDPR. The User maintains exclusive controller-like custody over their own data on their local machine.
- Data Subject Rights: Since no personal data is ever collected or processed by the Developer, requests for access, rectification, erasure ("right to be forgotten"), restriction, or portability under GDPR Articles 15-22 are technically inapplicable, as the Developer holds zero data to act upon.

C. Turkish KVKK Compliance Statement
Pursuant to the Law on the Protection of Personal Data No. 6698 ("KVKK") of the Republic of Türkiye:
- Data Controller Status: Because the Software operates completely offline and does not collect, record, process, or transfer any personal data to third parties or abroad, the Developer does not qualify as a "Data Controller" (Veri Sorumlusu) under the KVKK.
- Data Subject Rights: Your rights under Article 11 of the KVKK (including the right to request access, correction, or deletion of personal data) are technically inapplicable, as the Developer does not collect, hold, or possess any of your data. The security and absolute governance of your data remain solely under your local control.

D. California CCPA/CPRA Compliance Statement
Pursuant to the California Consumer Privacy Act, as amended by the California Privacy Rights Act (CCPA/CPRA):
- No Sale or Sharing: The Developer does not sell and does not share consumer personal information. The Software has zero commercial tracking mechanisms.
- Notice at Collection: Because the Software collects 0% personal information from California residents, no consumer profiles are built, and no financial incentives are offered.

⚠️ CRITICAL SECURITY WARNING: NO BACKDOORS & NO RECOVERY
Because the Software operates on a pure Zero-Knowledge model, you explicitly acknowledge that:
- You are solely responsible for the management and safekeeping of your passwords and cryptographic keys (including public and secret keys).
- THERE IS NO RECOVERY MECHANISM. There is no password reset tool, no cloud backup, and no administrative "backdoor."
- PERMANENT DATA LOSS: If you forget your password or lose your secret key, your encrypted data becomes permanently unrecoverable. The Developer cannot decrypt your files or bypass the encryption under any legal, technical, or practical circumstance.

3. CRYPTOGRAPHIC STANDARDS & DATA INTEGRITY
The Software utilizes high-grade, post-quantum hybrid cryptographic standards to ensure local data confidentiality:
- Symmetric Encryption: Argon2id or PBKDF2 for key derivation, combined with AES-256-GCM for Authenticated Encryption.
- Asymmetric Hybrid KEM: Combines classical X25519 with Post-Quantum Cryptography standard ML-KEM-768 (Kyber).
- Digital Signatures: Hybrid implementation of Ed25519 and Post-Quantum ML-DSA-65 (Dilithium).
- Integrity Verification: Utilizes a SHA-256-based Merkle Tree structure. Any unauthorized bit-level alteration or tampering with an encrypted file will cause the decryption sequence to fail and halt immediately.

4. FILE SYSTEM ACCESS AND OPERATING SYSTEM PERMISSIONS
The Software requests local file system permissions only when actively prompted by the User. It interacts exclusively with files explicitly selected by the User via the operating system's standard File Picker interface. The Software writes encrypted data as a new file in your designated target directory and will not delete or overwrite source files unless explicitly commanded by the User.

5. DISCLAIMER OF WARRANTIES
THE SOFTWARE IS PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE DEVELOPER EXPRESSLY DISCLAIMS ALL WARRANTIES, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. THE DEVELOPER DOES NOT WARRANT THAT THE SOFTWARE WILL BE COMPLETELY ERROR-FREE, UNINTERRUPTED, OR INVULNERABLE TO ALL FUTURE COMPUTATIONAL THREATS.

6. LIMITATION OF LIABILITY
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE DEVELOPER, AUTHORS, OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF DATA, PASSWORD LOSS, CORRUPTION OF ENCRYPTED FILES, LOSS OF PROFITS, OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF, OR INABILITY TO USE, THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

7. INDEMNIFICATION
You agree to indemnify, defend, and hold harmless the Developer from and against any and all claims, liabilities, damages, losses, or expenses (including reasonable legal and attorneys' fees) arising out of or in any way connected with your misuse of the Software, your violation of this Agreement, or your infringement of any third-party rights.

8. GOVERNING LAW AND SEVERABILITY
If any provision of this Agreement is found to be invalid or unenforceable by a court of competent jurisdiction, that provision shall be limited or eliminated to the minimum extent necessary, and the remaining provisions shall remain in full force and effect. This Agreement constitutes the entire contract between the User and the Developer regarding the Software.

BY PROCEEDING, YOU ACKNOWLEDGE THAT YOU HAVE READ THIS AGREEMENT, UNDERSTAND IT, AGREE TO BE BOUND BY ITS LEGAL CLAUSES, AND ACCEPT ABSOLUTE RESPONSIBILITY FOR YOUR PASSWORDS AND CRYPTOGRAPHIC KEYS.`;
