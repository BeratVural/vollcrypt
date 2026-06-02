import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save as tauriSave } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openUrl } from "@tauri-apps/plugin-opener";
import "./App.css";

type Tab = "file" | "text" | "key";
type Mode = "password" | "recipient" | "threshold";
type Action = "encrypt" | "decrypt" | "verify" | "seal";

function App() {
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
  const [sourceFile, setSourceFile] = useState("");
  const [destFile, setDestFile] = useState("");
  const [password, setPassword] = useState("");
  const [kdfChoice, setKdfChoice] = useState("Argon2id");
  const [recipientKey, setRecipientKey] = useState("");

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
      const file = await open({
        multiple: false,
        directory: false,
        title: "Select Source File",
      });
      if (typeof file === "string" && file) {
        setSourceFile(file);
        if (fileAction === "encrypt") {
          setDestFile(file + ".voll");
        } else {
          if (file.endsWith(".voll")) {
            let base = file.substring(0, file.length - 5);
            if (base.endsWith("_text")) {
              base = base.substring(0, base.length - 5) + ".txt";
            }
            setDestFile(base);
          } else {
            if (file.endsWith("_text")) {
              setDestFile(file.substring(0, file.length - 5) + ".txt");
            } else {
              setDestFile(file + ".dec");
            }
          }
        }
      }
    } catch (err: any) {
      showStatus("error", `File selection failed: ${err}`);
    }
  };

  const handlePickDest = async () => {
    try {
      const file = await tauriSave({
        title: "Select Destination Path",
        defaultPath: destFile || undefined,
      });
      if (file) {
        setDestFile(file);
      }
    } catch (err: any) {
      showStatus("error", `Destination selection failed: ${err}`);
    }
  };

  const handleFileProcess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sourceFile) {
      showStatus("error", "Source file path is required.");
      return;
    }
    if ((fileAction === "encrypt" || fileAction === "decrypt") && !destFile) {
      showStatus("error", "Source and destination paths are required.");
      return;
    }

    setLoading(true);
    setStatus({ type: "info", msg: "Processing... Please wait." });
    setVerifyReport(null);
    setSealedInspection(null);

    try {
      if (fileAction === "encrypt") {
        if (activeMode === "password") {
          if (!password) throw new Error("Encryption password is required.");
          await invoke("encrypt_file_password", {
            sourcePath: sourceFile,
            destPath: destFile,
            password,
            kdfChoice,
          });
        } else if (activeMode === "recipient") {
          if (!recipientKey) throw new Error("Recipient Public Key is required.");
          await invoke("encrypt_file_recipient", {
            sourcePath: sourceFile,
            destPath: destFile,
            recipientPkHex: recipientKey.trim(),
          });
        } else {
          if (thresholdT < 2) throw new Error("Threshold (t) must be at least 2.");
          if (thresholdN < thresholdT) throw new Error("Total shares (n) must be greater than or equal to threshold (t).");
          const shares: string[] = await invoke("encrypt_file_threshold", {
            sourcePath: sourceFile,
            destPath: destFile,
            t: thresholdT,
            n: thresholdN,
          });
          setGeneratedShares(shares);
        }
        showStatus("success", activeMode === "threshold" ? "File encrypted and SSS shares generated successfully." : "File successfully encrypted.");
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
            sourcePath: sourceFile,
            destPath: destFile,
            password,
            shield: shieldPolicy,
          });
        } else if (activeMode === "recipient") {
          if (!recipientKey) throw new Error("Recipient Secret Key is required.");
          await invoke("decrypt_file_recipient", {
            sourcePath: sourceFile,
            destPath: destFile,
            recipientSkHex: recipientKey.trim(),
            shield: shieldPolicy,
          });
        } else {
          const parsedShares = inputShares
            .split("\n")
            .map(s => s.trim())
            .filter(s => s.length > 0);
          if (parsedShares.length === 0) throw new Error("Please paste at least t shares.");
          await invoke("decrypt_file_threshold", {
            sourcePath: sourceFile,
            destPath: destFile,
            shares: parsedShares,
            shield: shieldPolicy,
          });
        }
        showStatus("success", activeMode === "threshold" ? "File successfully decrypted using SSS shares." : "File successfully decrypted.");
      } else if (fileAction === "verify") {
        const policy = {
          releaseMode: verifyReleaseMode,
          signature: verifySignaturePolicy,
          rollbackPin: verifyRollbackPin ? parseInt(verifyRollbackPin, 10) : null,
          founderAnchor: verifyFounderAnchor,
          onTamper: verifyOnTamper,
        };
        const report: string = await invoke("verify_container_file", {
          path: sourceFile,
          policy,
        });
        setVerifyReport(report);
        if (report === "ContainerSealed") {
          showStatus("info", "Verification check: Container is Sealed.");
          try {
            const inspectRes = await invoke("inspect_sealed_file", { path: sourceFile });
            setSealedInspection(inspectRes);
          } catch (inspectErr) {
            console.error("Failed to inspect sealed container:", inspectErr);
          }
        } else if (report === "Success" || report.includes("Success")) {
          showStatus("success", "Verification check: Integrity signature checks passed.");
        } else {
          showStatus("error", `Verification check: Tampering/validation issue detected: ${report}`);
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
          path: sourceFile,
          mode: sealMode,
          reason: sealReason || null,
          signInfo,
        });
        showStatus("success", `File container successfully ${sealMode === "purge" ? "purged" : "sealed"}.`);
        setSealConfirmText("");
      }
    } catch (err: any) {
      if (err === "ContainerSealed" || String(err).includes("ContainerSealed")) {
        showStatus("error", "ContainerSealed");
      } else {
        showStatus("error", err.message || String(err));
      }
    } finally {
      setLoading(false);
    }
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
  };

  return (
    <div className="window-frame">
      {/* Custom Titlebar */}
      <div className="custom-titlebar" data-tauri-drag-region>
        <div className="titlebar-brand" data-tauri-drag-region>
          <span className="brand-text" data-tauri-drag-region>
            <span className="brand-voll" data-tauri-drag-region>VOLL</span>
            <span className="brand-crypt" data-tauri-drag-region>crypt</span>
          </span>
          <span className="titlebar-version" data-tauri-drag-region>v0.2.0 (Windows)</span>
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
              setSourceFile("");
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
              setSourceFile("");
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
            onClick={() => {
              setActiveTab("key");
              setPassword("");
              setRecipientKey("");
              setSourceFile("");
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
                  style={{ flex: 1 }}
                  onClick={() => {
                    setFileAction("encrypt");
                    setSourceFile("");
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
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "decrypt" ? "active" : ""}`}
                  style={{ flex: 1 }}
                  onClick={() => {
                    setFileAction("decrypt");
                    setSourceFile("");
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
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "verify" ? "active" : ""}`}
                  style={{ flex: 1 }}
                  onClick={() => {
                    setFileAction("verify");
                    setSourceFile("");
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
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "seal" ? "active" : ""}`}
                  style={{ flex: 1 }}
                  onClick={() => {
                    setFileAction("seal");
                    setSourceFile("");
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
                </button>
              </div>

              {(fileAction === "encrypt" || fileAction === "decrypt") && (
                <div className="segmented-control" style={{ display: "flex", width: "100%" }}>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "password" ? "active" : ""}`}
                    style={{ flex: 1 }}
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
                  </button>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "recipient" ? "active" : ""}`}
                    style={{ flex: 1 }}
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
                  </button>
                  <button
                    type="button"
                    className={`segment-btn ${activeMode === "threshold" ? "active" : ""}`}
                    style={{ flex: 1 }}
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
                  </button>
                </div>
              )}
            </div>

            <div className="form-group">
              <label>Source File</label>
              <div className="file-picker">
                <div className="file-path">{sourceFile || "No file selected..."}</div>
                <button type="button" className="file-picker-btn" onClick={handlePickSource}>
                  Browse
                </button>
              </div>
            </div>

            {(fileAction === "encrypt" || fileAction === "decrypt") && (
              <div className="form-group">
                <label>Destination File</label>
                <div className="file-picker">
                  <div className="file-path">{destFile || "Select save path..."}</div>
                  <button type="button" className="file-picker-btn" onClick={handlePickDest}>
                    Browse
                  </button>
                </div>
              </div>
            )}

            {(fileAction === "encrypt" || fileAction === "decrypt") && (
              activeMode === "password" ? (
                <div className="form-row">
                  <div className="form-group" style={{ flex: 2 }}>
                    <label>Password</label>
                    <input
                      type="password"
                      className="text-input"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter wrap password..."
                    />
                  </div>
                  {fileAction === "encrypt" && (
                    <div className="form-group" style={{ flex: 1 }}>
                      <label>KDF</label>
                      <select
                        className="select-input"
                        value={kdfChoice}
                        onChange={(e) => setKdfChoice(e.target.value)}
                      >
                        <option value="Argon2id">Argon2id</option>
                        <option value="PBKDF2">PBKDF2</option>
                      </select>
                    </div>
                  )}
                </div>
              ) : activeMode === "recipient" ? (
                <div className="form-group">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <label>{fileAction === "encrypt" ? "Recipient Public Key" : "Your Secret Key"}</label>
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
                </div>
              ) : (
                fileAction === "encrypt" ? (
                  <div className="form-row">
                    <div className="form-group">
                      <label>Threshold (t)</label>
                      <input
                        type="number"
                        className="text-input"
                        value={thresholdT}
                        min={2}
                        max={thresholdN}
                        onChange={(e) => setThresholdT(parseInt(e.target.value) || 2)}
                        placeholder="Required shares (t)"
                      />
                    </div>
                    <div className="form-group">
                      <label>Total Shares (n)</label>
                      <input
                        type="number"
                        className="text-input"
                        value={thresholdN}
                        min={thresholdT}
                        max={255}
                        onChange={(e) => setThresholdN(parseInt(e.target.value) || 3)}
                        placeholder="Total shares to generate (n)"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="form-group">
                    <label>Pasted Shares (One share per line)</label>
                    <textarea
                      className="text-input"
                      value={inputShares}
                      onChange={(e) => setInputShares(e.target.value)}
                      placeholder="Paste shares here (one per line, e.g. VOLL_SHARE_...)"
                      style={{ minHeight: "120px" }}
                    />
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
                    <label>Release Mode</label>
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
                    <label>Signature Policy</label>
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
                    <label>Rollback Pin Epoch</label>
                    <input
                      type="number"
                      className="text-input"
                      value={verifyRollbackPin}
                      onChange={(e) => setVerifyRollbackPin(e.target.value)}
                      placeholder="e.g. 1 (optional)"
                    />
                  </div>
                  <div className="form-group">
                    <label>On Tamper Reaction</label>
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
                  <label htmlFor="verifyFounderAnchor" style={{ marginBottom: 0, textTransform: "none", cursor: "pointer" }}>
                    Enforce Founder Anchor check
                  </label>
                </div>
              </div>
            )}

            {fileAction === "seal" && (
              <div className="seal-settings" style={{ borderTop: "1px solid #1f1f23", paddingTop: "14px", marginTop: "14px" }}>
                <div style={{ backgroundColor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.25)", borderRadius: "6px", padding: "12px", marginBottom: "14px" }}>
                  <h4 style={{ fontSize: "11px", fontWeight: "700", color: "#f87171", marginBottom: "6px", textTransform: "uppercase" }}>
                    ⚠️ CRITICAL WARNING: IRREVERSIBLE OPERATION
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
                    <label>Seal Mode</label>
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
                    <label>Reason / Audit Label</label>
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
                  <label htmlFor="sealSignEnabled" style={{ marginBottom: 0, textTransform: "none", cursor: "pointer" }}>
                    Sign Sealed Marker (Recommended for v2/v3)
                  </label>
                </div>

                {sealSignEnabled && (
                  <div style={{ backgroundColor: "#141416", border: "1px solid #1f1f23", borderRadius: "6px", padding: "10px", marginBottom: "14px" }}>
                    <div className="form-row">
                      <div className="form-group" style={{ flex: 1 }}>
                        <label>Signer Type</label>
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
                        <label>Key Log ID (Hex)</label>
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
                      <label>Signer Public Key (Hex)</label>
                      <input
                        type="text"
                        className="text-input"
                        value={sealSignerPk}
                        onChange={(e) => setSealSignerPk(e.target.value)}
                        placeholder="Paste public key hex..."
                      />
                    </div>
                    <div className="form-group">
                      <label>Signer Secret Key (Hex)</label>
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
                  <label style={{ color: "#f87171" }}>Type "SEAL" to confirm</label>
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
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ fontSize: "8px", padding: "2px 6px" }}
                          onClick={() => copyToClipboard(share, `Share #${idx + 1}`)}
                        >
                          Copy Share
                        </button>
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

              <div className="segmented-control">
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "password" ? "active" : ""}`}
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
                </button>
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "recipient" ? "active" : ""}`}
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
                </button>
                <button
                  type="button"
                  className={`segment-btn ${activeMode === "threshold" ? "active" : ""}`}
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
                </button>
              </div>
            </div>

            <div className="form-group">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <label>{textAction === "encrypt" ? "Plaintext Message" : "Hex Container Ciphertext"}</label>
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
            </div>

            {activeMode === "password" ? (
              <div className="form-row">
                <div className="form-group" style={{ flex: 2 }}>
                  <label>Password</label>
                  <input
                    type="password"
                    className="text-input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter wrap password..."
                  />
                </div>
                {textAction === "encrypt" && (
                  <div className="form-group" style={{ flex: 1 }}>
                    <label>KDF</label>
                    <select
                      className="select-input"
                      value={kdfChoice}
                      onChange={(e) => setKdfChoice(e.target.value)}
                    >
                      <option value="Argon2id">Argon2id</option>
                      <option value="PBKDF2">PBKDF2</option>
                    </select>
                  </div>
                )}
              </div>
            ) : activeMode === "recipient" ? (
              <div className="form-group">
                <label>{textAction === "encrypt" ? "Recipient Public Key" : "Your Secret Key"}</label>
                <input
                  type="text"
                  className="text-input"
                  value={recipientKey}
                  onChange={(e) => setRecipientKey(e.target.value)}
                  placeholder="Paste hexadecimal key..."
                />
              </div>
            ) : (
              textAction === "encrypt" ? (
                <div className="form-row">
                  <div className="form-group">
                    <label>Threshold (t)</label>
                    <input
                      type="number"
                      className="text-input"
                      value={thresholdT}
                      min={2}
                      max={thresholdN}
                      onChange={(e) => setThresholdT(parseInt(e.target.value) || 2)}
                      placeholder="Required shares (t)"
                    />
                  </div>
                  <div className="form-group">
                    <label>Total Shares (n)</label>
                    <input
                      type="number"
                      className="text-input"
                      value={thresholdN}
                      min={thresholdT}
                      max={255}
                      onChange={(e) => setThresholdN(parseInt(e.target.value) || 3)}
                      placeholder="Total shares to generate (n)"
                    />
                  </div>
                </div>
              ) : (
                <div className="form-group">
                  <label>Pasted Shares (One share per line)</label>
                  <textarea
                    className="text-input"
                    value={inputShares}
                    onChange={(e) => setInputShares(e.target.value)}
                    placeholder="Paste shares here (one per line, e.g. VOLL_SHARE_...)"
                    style={{ minHeight: "120px" }}
                  />
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
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ fontSize: "8px", padding: "2px 6px" }}
                          onClick={() => copyToClipboard(share, `Share #${idx + 1}`)}
                        >
                          Copy Share
                        </button>
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
              <button type="button" className="btn-primary" onClick={handleGenerateKeys} disabled={loading} style={{ margin: "12px 0 20px" }}>
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
                    <span className="display-box-title">Public Key (Share openly)</span>
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button type="button" className="btn-secondary" onClick={() => copyToClipboard(generatedPk, "Public key")}>Copy</button>
                      <button type="button" className="btn-secondary" onClick={() => saveTextToFile("Public Key", generatedPk, "vollcrypt_public_key.pub")}>Save File</button>
                    </div>
                  </div>
                  <div className="display-box" style={{ maxHeight: "70px" }}>{generatedPk}</div>
                </div>

                <div className="key-section" style={{ marginTop: "16px" }}>
                  <div className="display-box-header">
                    <span className="display-box-title" style={{ color: "#f87171" }}>Secret Key (Keep secure!)</span>
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
      </div>
    </div>
  </div>
  );
}

export default App;
