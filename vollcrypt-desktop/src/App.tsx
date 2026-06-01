import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save as tauriSave } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openUrl } from "@tauri-apps/plugin-opener";
import "./App.css";

type Tab = "file" | "text" | "key";
type Mode = "password" | "recipient";
type Action = "encrypt" | "decrypt";

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

  // Text states
  const [inputText, setInputText] = useState("");
  const [outputText, setOutputText] = useState("");

  // Key generator states
  const [generatedPk, setGeneratedPk] = useState("");
  const [generatedSk, setGeneratedSk] = useState("");

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
    if (!sourceFile || !destFile) {
      showStatus("error", "Source and destination paths are required.");
      return;
    }

    setLoading(true);
    setStatus({ type: "info", msg: "Processing... Please wait." });

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
        } else {
          if (!recipientKey) throw new Error("Recipient Public Key is required.");
          await invoke("encrypt_file_recipient", {
            sourcePath: sourceFile,
            destPath: destFile,
            recipientPkHex: recipientKey.trim(),
          });
        }
        showStatus("success", "File successfully encrypted.");
      } else {
        if (activeMode === "password") {
          if (!password) throw new Error("Decryption password is required.");
          await invoke("decrypt_file_password", {
            sourcePath: sourceFile,
            destPath: destFile,
            password,
          });
        } else {
          if (!recipientKey) throw new Error("Recipient Secret Key is required.");
          await invoke("decrypt_file_recipient", {
            sourcePath: sourceFile,
            destPath: destFile,
            recipientSkHex: recipientKey.trim(),
          });
        }
        showStatus("success", "File successfully decrypted.");
      }
    } catch (err: any) {
      showStatus("error", err.message || String(err));
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
        } else {
          if (!recipientKey) throw new Error("Recipient Public Key is required.");
          result = await invoke("encrypt_text_recipient", {
            text: inputText,
            recipientPkHex: recipientKey.trim(),
          });
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
        } else {
          if (!recipientKey) throw new Error("Secret Key is required for decryption.");
          result = await invoke("decrypt_text_recipient", {
            ciphertextHex: inputText.trim(),
            recipientSkHex: recipientKey.trim(),
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
              setStatus(null);
            }}
          >
            Keypair
          </div>
        </nav>

        {/* File Tab */}
        {activeTab === "file" && (
          <form onSubmit={handleFileProcess}>
            <div className="settings-row">
              <div className="segmented-control">
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "encrypt" ? "active" : ""}`}
                  onClick={() => {
                    setFileAction("encrypt");
                    setSourceFile("");
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
                    setStatus(null);
                  }}
                >
                  Encrypt
                </button>
                <button
                  type="button"
                  className={`segment-btn ${fileAction === "decrypt" ? "active" : ""}`}
                  onClick={() => {
                    setFileAction("decrypt");
                    setSourceFile("");
                    setDestFile("");
                    setPassword("");
                    setRecipientKey("");
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
                    setStatus(null);
                  }}
                >
                  Hybrid KEM
                </button>
              </div>
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

            <div className="form-group">
              <label>Destination File</label>
              <div className="file-picker">
                <div className="file-path">{destFile || "Select save path..."}</div>
                <button type="button" className="file-picker-btn" onClick={handlePickDest}>
                  Browse
                </button>
              </div>
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
            ) : (
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
            )}

            <div style={{ marginTop: "24px" }}>
              <button type="submit" className="btn-primary" disabled={loading}>
                {fileAction === "encrypt" ? "Encrypt File" : "Decrypt File"}
              </button>
            </div>
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
                    setStatus(null);
                  }}
                >
                  Hybrid KEM
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
            ) : (
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
            {status.msg}
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
