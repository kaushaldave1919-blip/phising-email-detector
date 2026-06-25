const scanForm = document.getElementById("scanForm");
const emailContent = document.getElementById("emailContent");
const scanButton = document.getElementById("scanButton");
const clearButton = document.getElementById("clearButton");
const loadingPanel = document.getElementById("loadingPanel");
const errorBox = document.getElementById("errorBox");

const resultsSection = document.getElementById("resultsSection");
const indicatorsSection = document.getElementById("indicatorsSection");
const predictionValue = document.getElementById("predictionValue");
const modelValue = document.getElementById("modelValue");
const riskScoreValue = document.getElementById("riskScoreValue");
const riskLevelValue = document.getElementById("riskLevelValue");
const confidenceValue = document.getElementById("confidenceValue");
const scoreRing = document.getElementById("scoreRing");
const reportLink = document.getElementById("reportLink");
const keywordsList = document.getElementById("keywordsList");
const urlsList = document.getElementById("urlsList");

const charCount = document.getElementById("charCount");
const wordCount = document.getElementById("wordCount");
const lineCount = document.getElementById("lineCount");
const urlCount = document.getElementById("urlCount");

const urlRegex = /\b(?:https?:\/\/|www\.)[^\s<>'"()]+/gi;

function setScanning(isScanning) {
    scanButton.disabled = isScanning;
    scanButton.classList.toggle("is-scanning", isScanning);
    loadingPanel.hidden = !isScanning;
}

function setError(message) {
    errorBox.textContent = message;
    errorBox.hidden = !message;
}

function updateLocalStats() {
    const text = emailContent.value;
    const words = text.trim().match(/\b[\w'-]+\b/g) || [];
    const urls = text.match(urlRegex) || [];
    const lines = text.length ? text.split(/\r\n|\r|\n/).length : 0;

    charCount.textContent = text.length.toLocaleString();
    wordCount.textContent = words.length.toLocaleString();
    lineCount.textContent = lines.toLocaleString();
    urlCount.textContent = urls.length.toLocaleString();
}

function riskColor(level) {
    if (level === "High") {
        return "#ff5c7a";
    }
    if (level === "Medium") {
        return "#ffcc66";
    }
    return "#37e89b";
}

function resetResultClasses() {
    document.querySelector(".verdict-card").classList.remove("is-phishing", "is-safe");
    document.querySelector(".level-card").classList.remove("is-low", "is-medium", "is-high");
}

function renderEmptyItem(list, text) {
    const item = document.createElement("li");
    item.className = "empty-state";
    item.textContent = text;
    list.appendChild(item);
}

function renderKeywords(keywords) {
    keywordsList.replaceChildren();

    if (!keywords.length) {
        renderEmptyItem(keywordsList, "No suspicious keywords detected.");
        return;
    }

    keywords.forEach((keyword) => {
        const item = document.createElement("li");
        item.textContent = keyword;
        keywordsList.appendChild(item);
    });
}

function renderUrls(urlDetails) {
    urlsList.replaceChildren();

    if (!urlDetails.length) {
        renderEmptyItem(urlsList, "No URLs detected.");
        return;
    }

    urlDetails.forEach((entry) => {
        const item = document.createElement("li");
        const urlValue = document.createElement("span");
        const reasons = document.createElement("span");

        urlValue.className = "url-value";
        reasons.className = "url-reasons";
        urlValue.textContent = entry.url;
        reasons.textContent = entry.reasons.join(", ");

        item.append(urlValue, reasons);
        urlsList.appendChild(item);
    });
}

function renderResults(data) {
    resetResultClasses();

    predictionValue.textContent = data.prediction;
    modelValue.textContent = `Model: ${data.model_prediction}`;
    riskScoreValue.textContent = `${data.risk_score}%`;
    riskLevelValue.textContent = data.risk_level;
    confidenceValue.textContent = `Confidence: ${data.confidence}%`;
    scoreRing.style.setProperty("--score", data.risk_score);
    scoreRing.style.background = `radial-gradient(circle, var(--surface-2) 56%, transparent 58%), conic-gradient(${riskColor(data.risk_level)} ${data.risk_score}%, rgba(158, 176, 168, 0.18) 0)`;

    document.querySelector(".verdict-card").classList.add(data.prediction === "Phishing" ? "is-phishing" : "is-safe");
    document.querySelector(".level-card").classList.add(`is-${data.risk_level.toLowerCase()}`);

    reportLink.href = data.report_url;
    reportLink.hidden = false;

    renderKeywords(data.keywords_found);
    renderUrls(data.url_details);

    charCount.textContent = data.statistics.characters.toLocaleString();
    wordCount.textContent = data.statistics.words.toLocaleString();
    lineCount.textContent = data.statistics.lines.toLocaleString();
    urlCount.textContent = data.statistics.urls.toLocaleString();

    resultsSection.hidden = false;
    indicatorsSection.hidden = false;
}

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("");

    const emailText = emailContent.value.trim();
    if (!emailText) {
        setError("Please paste email content before scanning.");
        resultsSection.hidden = true;
        indicatorsSection.hidden = true;
        return;
    }

    setScanning(true);

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ email_content: emailText }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Scan failed.");
        }

        renderResults(data);
    } catch (error) {
        setError(error.message);
    } finally {
        setScanning(false);
    }
});

clearButton.addEventListener("click", () => {
    emailContent.value = "";
    updateLocalStats();
    setError("");
    resultsSection.hidden = true;
    indicatorsSection.hidden = true;
    emailContent.focus();
});

emailContent.addEventListener("input", updateLocalStats);
updateLocalStats();
