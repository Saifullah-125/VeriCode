/**
 * VeriCode 2.0 - Independent Multi-Language Workspace State Manager
 * Synced with templates/index.html (#code, .lang[data-l], #sample, #clear, #file, #go)
 */

const VeriCodeWorkspace = (() => {
  const SUPPORTED_LANGUAGES = ["c", "cpp", "python", "java"];

  const PLACEHOLDERS = {
    c: `// Write C code here...\n#include <stdio.h>\n\nint main(void) {\n    return 0;\n}`,
    cpp: `// Write C++ code here...\n#include <iostream>\n\nint main() {\n    return 0;\n}`,
    python: `# Write Python code here...\ndef main():\n    pass\n\nif __name__ == "__main__":\n    main()`,
    java: `// Write Java code here...\npublic class Main {\n    public static void main(String[] args) {\n    }\n}`
  };

  const editorDocuments = {
    c: "",
    cpp: "",
    python: "",
    java: ""
  };

  let activeLanguage = null;
  let editorEl = null;
  let lastAnalyzedSnapshot = null;

  function normalizeLang(raw) {
    if (!raw) return null;
    const v = String(raw).trim().toLowerCase();
    if (v === "c") return "c";
    if (v === "cpp" || v === "c++") return "cpp";
    if (v === "python" || v === "py") return "python";
    if (v === "java") return "java";
    return null;
  }

  function saveCurrent() {
    if (activeLanguage && editorEl) {
      editorDocuments[activeLanguage] = editorEl.value;
    }
  }

  function applyPlaceholder(targetLang) {
    if (!editorEl) return;
    if (targetLang && PLACEHOLDERS[targetLang]) {
      editorEl.setAttribute("placeholder", PLACEHOLDERS[targetLang]);
    } else {
      editorEl.setAttribute("placeholder", "Paste source code here, load a sample, or upload a file.");
    }
  }

  function makeSnapshot(targetLang, codeText) {
    const safeLang = targetLang || "none";
    const safeCode = codeText || "";
    let h = 0;
    for (let i = 0; i < safeCode.length; i++) {
      h = ((h << 5) - h + safeCode.charCodeAt(i)) | 0;
    }
    return `${safeLang}:${safeCode.length}:${h}`;
  }

  function updateStaleBanner() {
    const banner = document.getElementById("stale-results-banner");
    if (!banner || !lastAnalyzedSnapshot || !editorEl) return;
    const currentSnap = makeSnapshot(activeLanguage, editorEl.value);
    banner.style.display = currentSnap !== lastAnalyzedSnapshot ? "block" : "none";
  }

  function selectLanguage(nextRaw, { keepCurrentIfSame = true } = {}) {
    const nextLang = normalizeLang(nextRaw);
    if (!nextLang) return null;

    if (activeLanguage && editorEl && (!keepCurrentIfSame || nextLang !== activeLanguage)) {
      editorDocuments[activeLanguage] = editorEl.value;
    }

    activeLanguage = nextLang;

    document.querySelectorAll(".lang").forEach((card) => {
      card.classList.toggle("on", normalizeLang(card.dataset.l) === activeLanguage);
    });

    if (editorEl) {
      editorEl.value = editorDocuments[activeLanguage] || "";
    }

    applyPlaceholder(activeLanguage);
    updateStaleBanner();
    return activeLanguage;
  }

  function setActiveCode(codeText, targetLangRaw = null) {
    const targetLang = normalizeLang(targetLangRaw) || activeLanguage;
    if (targetLang && targetLang !== activeLanguage) {
      selectLanguage(targetLang);
    }
    if (targetLang) {
      editorDocuments[targetLang] = codeText || "";
    }
    if (editorEl) {
      editorEl.value = codeText || "";
    }
    updateStaleBanner();
  }

  function clearActiveLanguage() {
    if (activeLanguage) {
      editorDocuments[activeLanguage] = "";
    }
    if (editorEl) {
      editorEl.value = "";
    }
    applyPlaceholder(activeLanguage);
    updateStaleBanner();
  }

  function getPayload() {
    saveCurrent();
    const code = editorEl ? editorEl.value : (activeLanguage ? editorDocuments[activeLanguage] : "");
    return {
      code,
      language: activeLanguage,
      snapshot_id: makeSnapshot(activeLanguage, code)
    };
  }

  function markAnalyzed(payload) {
    if (payload && payload.snapshot_id) {
      lastAnalyzedSnapshot = payload.snapshot_id;
    } else {
      const cur = getPayload();
      lastAnalyzedSnapshot = cur.snapshot_id;
    }
    updateStaleBanner();
  }

  function init({ textareaSelector = "#code" } = {}) {
    editorEl = document.querySelector(textareaSelector);
    if (editorEl) {
      editorEl.addEventListener("input", () => {
        saveCurrent();
        updateStaleBanner();
      });
    }
    applyPlaceholder(null);
  }

  return {
    init,
    selectLanguage,
    setActiveCode,
    clearActiveLanguage,
    getPayload,
    markAnalyzed,
    getActiveLanguage: () => activeLanguage,
    getAllDocuments: () => ({ ...editorDocuments })
  };
})();